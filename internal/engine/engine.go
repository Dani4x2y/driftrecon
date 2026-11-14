// Package engine runs the scan pipeline: discovery, resolution,
// fingerprinting and storage.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/collector"
	"github.com/Dani4x2y/driftrecon/internal/collector/resolve"
	"github.com/Dani4x2y/driftrecon/internal/fingerprint"
	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/scope"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

// batchSize is how many snapshots are written per transaction.
const batchSize = 200

// Options tunes a scan.
type Options struct {
	Profile     model.Profile
	Concurrency int
	// MaxHosts fails a scan that would cover more hosts than expected,
	// before anything is sent to them.
	MaxHosts int
	// Logger receives progress and non-fatal errors. It defaults to
	// discarding them.
	Logger *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Engine executes scans.
type Engine struct {
	store    *storage.Store
	sources  []collector.Source
	resolver *resolve.Resolver
	opts     Options
	log      *slog.Logger
	now      func() time.Time
}

// New wires an Engine. The resolver may be nil for the passive profile.
func New(store *storage.Store, sources []collector.Source, resolver *resolve.Resolver, opts Options) (*Engine, error) {
	if _, err := model.ParseProfile(string(opts.Profile)); err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}
	switch {
	case opts.Profile != model.ProfilePassive && resolver == nil:
		return nil, fmt.Errorf("engine: profile %q needs a resolver", opts.Profile)
	case opts.Concurrency < 1:
		return nil, errors.New("engine: concurrency must be positive")
	case opts.MaxHosts < 1:
		return nil, errors.New("engine: max hosts must be positive")
	}

	e := &Engine{
		store:    store,
		sources:  sources,
		resolver: resolver,
		opts:     opts,
		log:      opts.Logger,
		now:      opts.Now,
	}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e, nil
}

// Scan runs one scan of target. The returned scan is non-nil whenever a scan
// record was created, which includes scans that failed or were interrupted.
func (e *Engine) Scan(ctx context.Context, target *storage.Target) (*storage.Scan, error) {
	sc, err := scope.New(target.Rules)
	if err != nil {
		return nil, fmt.Errorf("engine: target %s: %w", target.Name, err)
	}

	scan, err := e.store.BeginScan(ctx, target.ID, e.opts.Profile, e.configHash(), fingerprint.Version, e.now())
	if err != nil {
		return nil, err
	}

	stats, runErr := e.run(ctx, sc, scan)

	status := storage.ScanCompleted
	switch {
	case runErr == nil:
	case errors.Is(runErr, context.Canceled):
		status, stats.Reason = storage.ScanAborted, "interrupted"
	case errors.Is(runErr, context.DeadlineExceeded):
		status, stats.Reason = storage.ScanAborted, "time limit reached"
	default:
		status, stats.Reason = storage.ScanFailed, runErr.Error()
	}

	// The record has to be closed even though ctx may already be cancelled.
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := e.store.FinishScan(closeCtx, scan, status, stats, e.now()); err != nil {
		return scan, errors.Join(runErr, err)
	}
	return scan, runErr
}

// configHash identifies the settings that decide what a scan is able to
// observe about an asset. Scans with different hashes are not comparable
// layer by layer.
func (e *Engine) configHash() string {
	sum := sha256.Sum256([]byte("profile=" + string(e.opts.Profile)))
	return hex.EncodeToString(sum[:])
}

type outcome struct {
	snap storage.Snapshot
	err  error
}

func (e *Engine) run(ctx context.Context, sc *scope.Scope, scan *storage.Scan) (model.ScanStats, error) {
	stats := model.ScanStats{States: make(map[model.State]int)}

	candidates, err := e.discover(ctx, sc, scan.TargetID, &stats)
	if err != nil {
		return stats, err
	}
	stats.Hosts = len(candidates)
	if stats.Hosts > e.opts.MaxHosts {
		return stats, fmt.Errorf("%d hosts in scope exceed the limit of %d: raise max_hosts or narrow the scope",
			stats.Hosts, e.opts.MaxHosts)
	}
	e.log.Info("discovery finished", "hosts", stats.Hosts)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan string)
	results := make(chan outcome, e.opts.Concurrency)

	go func() {
		defer close(jobs)
		for _, host := range slices.Sorted(maps.Keys(candidates)) {
			select {
			case jobs <- host:
			case <-ctx.Done():
				return
			}
		}
	}()

	var workers sync.WaitGroup
	for range e.opts.Concurrency {
		workers.Go(func() {
			for host := range jobs {
				snap, err := e.observe(ctx, sc, host, candidates[host])
				select {
				case results <- outcome{snap: snap, err: err}:
				case <-ctx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		})
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	// Workers only produce snapshots. All database writes happen here, on
	// one goroutine, in batches.
	var (
		batch  = make([]storage.Snapshot, 0, batchSize)
		done   int
		runErr error
	)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		created, err := e.store.SaveSnapshots(ctx, scan, batch)
		if err != nil {
			return err
		}
		stats.NewAssets += created
		for _, snap := range batch {
			stats.States[snap.State]++
		}
		done += len(batch)
		batch = batch[:0]
		e.log.Info("progress", "done", done, "total", stats.Hosts)
		return nil
	}

	for res := range results {
		switch {
		case runErr != nil:
			// Keep draining so the workers can exit.
		case res.err != nil:
			runErr = res.err
			cancel()
		default:
			batch = append(batch, res.snap)
			if len(batch) == batchSize {
				if runErr = flush(); runErr != nil {
					cancel()
				}
			}
		}
	}
	if runErr != nil {
		return stats, runErr
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	return stats, flush()
}

type sourceResult struct {
	root  string
	names []string
	err   error
}

// discover collects the hostnames to examine: the roots, everything known
// from earlier scans, and whatever the sources report now. Carrying known
// hosts forward keeps a source outage from looking like hosts disappearing.
// The result maps each host to the sources that reported it in this scan.
func (e *Engine) discover(ctx context.Context, sc *scope.Scope, targetID int64, stats *model.ScanStats) (map[string][]string, error) {
	found := make(map[string][]string)
	for _, root := range sc.Roots() {
		if sc.Contains(root) {
			found[root] = nil
		}
	}

	known, err := e.store.AssetKeys(ctx, targetID, model.KindHost)
	if err != nil {
		return nil, err
	}
	for _, host := range known {
		if sc.Contains(host) {
			found[host] = nil
		}
	}

	// Sources run side by side, but each one works through the roots one at
	// a time: a third-party service never sees parallel requests from a scan.
	results := make([][]sourceResult, len(e.sources))
	var wg sync.WaitGroup
	for i, src := range e.sources {
		wg.Go(func() {
			for _, root := range sc.Roots() {
				if ctx.Err() != nil {
					return
				}
				names, err := src.Enumerate(ctx, root)
				results[i] = append(results[i], sourceResult{root: root, names: names, err: err})
			}
		})
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for i, src := range e.sources {
		for _, res := range results[i] {
			inScope := make(map[string]struct{})
			for _, name := range res.names {
				host, err := scope.NormalizeHost(name)
				if err != nil || !sc.Contains(host) {
					continue
				}
				if _, dup := inScope[host]; dup {
					continue
				}
				inScope[host] = struct{}{}
				found[host] = append(found[host], src.Name())
			}

			stat := model.SourceStat{Source: src.Name(), Domain: res.root, Names: len(inScope)}
			if res.err != nil {
				stat.Error = res.err.Error()
				e.log.Warn("source failed", "source", src.Name(), "domain", res.root, "err", res.err)
			}
			stats.Sources = append(stats.Sources, stat)
		}
	}

	for host, sources := range found {
		slices.Sort(sources)
		found[host] = slices.Compact(sources)
	}
	return found, nil
}

// observe examines one host and turns the result into a snapshot. The only
// errors it returns are fatal to the scan; a failed lookup is recorded as a
// state of the host instead.
func (e *Engine) observe(ctx context.Context, sc *scope.Scope, host string, sources []string) (storage.Snapshot, error) {
	obs := model.HostObservation{Host: host}
	state := model.StateDiscovered

	if e.opts.Profile != model.ProfilePassive {
		dns, st, err := e.resolveHost(ctx, sc, host)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return storage.Snapshot{}, ctxErr
		}
		if err != nil {
			e.log.Warn("lookup failed", "host", host, "err", err)
		}
		obs.DNS, state = dns, st
	}

	data, err := json.Marshal(obs)
	if err != nil {
		return storage.Snapshot{}, fmt.Errorf("engine: encode observation of %s: %w", host, err)
	}
	layers := fingerprint.Host(obs)

	return storage.Snapshot{
		Kind:       model.KindHost,
		Key:        host,
		Host:       host,
		State:      state,
		FP:         layers.Composite(),
		FPDNS:      layers.DNS,
		Data:       data,
		ObservedAt: e.now(),
		Sources:    sources,
		Seen:       len(sources) > 0 || state == model.StateLive || state == model.StateWildcard,
	}, nil
}

// resolveHost looks a host up and classifies it. An observation is recorded
// in full or not at all: if any part of it could not be determined the host
// is reported as StateError without data, because a partial record would
// later be mistaken for a change.
func (e *Engine) resolveHost(ctx context.Context, sc *scope.Scope, host string) (*model.DNS, model.State, error) {
	res, err := e.resolver.Lookup(ctx, host)
	if err != nil {
		return nil, model.StateError, err
	}
	dns := &model.DNS{
		Rcode: res.Rcode,
		CNAME: res.CNAME,
		A:     addrStrings(res.A),
		AAAA:  addrStrings(res.AAAA),
	}

	if sc.IsRoot(host) {
		// Delegation is a property of the zone, so it is tracked at the
		// roots only. A root is also never a wildcard candidate.
		if dns.NS, err = e.resolver.NS(ctx, host); err != nil {
			return nil, model.StateError, err
		}
		if res.Resolved() {
			return dns, model.StateLive, nil
		}
		return dns, model.StateUnresolved, nil
	}

	if !res.Resolved() {
		return dns, model.StateUnresolved, nil
	}

	_, parent, _ := strings.Cut(host, ".")
	wildcard, err := e.resolver.Wildcard(ctx, parent)
	if err != nil {
		return nil, model.StateError, fmt.Errorf("wildcard probe of %s: %w", parent, err)
	}
	if wildcard.Matches(res) {
		return dns, model.StateWildcard, nil
	}
	return dns, model.StateLive, nil
}

func addrStrings(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}
	return out
}
