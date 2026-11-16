// Package engine runs the scan pipeline: discovery, resolution, probing,
// fingerprinting and storage.
package engine

import (
	"cmp"
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
	"github.com/Dani4x2y/driftrecon/internal/collector/probe"
	"github.com/Dani4x2y/driftrecon/internal/collector/resolve"
	"github.com/Dani4x2y/driftrecon/internal/fingerprint"
	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/scope"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

// batchSize is how many snapshots are written per transaction.
const batchSize = 200

// sourceProbe is recorded as the source of assets found by examining a
// host, as opposed to assets reported by a discovery source.
const sourceProbe = "probe"

// The reasons recorded for a known service that was not probed because of
// what happened to its host.
const (
	reasonUnresolved   = "host does not resolve"
	reasonLookupFailed = "dns lookup failed"
)

// Endpoint is a scheme and port on which every resolving host is checked
// for an HTTP service.
type Endpoint struct {
	Scheme string
	Port   uint16
}

// Options tunes a scan.
type Options struct {
	Profile     model.Profile
	Concurrency int
	// MaxHosts fails a scan that would cover more hosts than expected,
	// before anything is sent to them.
	MaxHosts int
	// Endpoints lists where HTTP services are looked for. Without any, or
	// without a prober, hosts are resolved and nothing more.
	Endpoints []Endpoint
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
	prober   *probe.Prober
	opts     Options
	log      *slog.Logger
	now      func() time.Time
}

// New wires an Engine. The resolver and the prober may be nil for the
// passive profile, which uses neither. The prober may also be nil to stop
// at name resolution.
func New(store *storage.Store, sources []collector.Source, resolver *resolve.Resolver, prober *probe.Prober, opts Options) (*Engine, error) {
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

	opts.Endpoints = slices.Clone(opts.Endpoints)
	slices.SortFunc(opts.Endpoints, func(a, b Endpoint) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Scheme, b.Scheme))
	})
	for i, ep := range opts.Endpoints {
		switch {
		case ep.Scheme != "http" && ep.Scheme != "https":
			return nil, fmt.Errorf("engine: endpoint scheme %q is neither http nor https", ep.Scheme)
		case ep.Port == 0:
			return nil, errors.New("engine: endpoint port must be positive")
		case i > 0 && opts.Endpoints[i-1].Port == ep.Port:
			return nil, fmt.Errorf("engine: port %d is listed more than once", ep.Port)
		}
	}
	// The passive profile sends nothing to the target, whatever else is
	// configured.
	if opts.Profile == model.ProfilePassive || prober == nil || len(opts.Endpoints) == 0 {
		prober, opts.Endpoints = nil, nil
	}

	e := &Engine{
		store:    store,
		sources:  sources,
		resolver: resolver,
		prober:   prober,
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
// layer by layer: a service that shows up because a port was added to the
// configuration is not a new service.
func (e *Engine) configHash() string {
	config := "profile=" + string(e.opts.Profile)
	if e.prober != nil {
		endpoints := make([]string, len(e.opts.Endpoints))
		for i, ep := range e.opts.Endpoints {
			endpoints[i] = fmt.Sprintf("%s:%d", ep.Scheme, ep.Port)
		}
		config += fmt.Sprintf(";endpoints=%s;private=%t", strings.Join(endpoints, ","), e.prober.AllowsPrivate())
	}
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}

type outcome struct {
	snaps []storage.Snapshot
	err   error
}

func (e *Engine) run(ctx context.Context, sc *scope.Scope, scan *storage.Scan) (model.ScanStats, error) {
	stats := model.ScanStats{
		States:        make(map[model.State]int),
		ServiceStates: make(map[model.State]int),
	}

	candidates, err := e.discover(ctx, sc, scan.TargetID, &stats)
	if err != nil {
		return stats, err
	}
	stats.Hosts = len(candidates)
	if stats.Hosts > e.opts.MaxHosts {
		return stats, fmt.Errorf("%d hosts in scope exceed the limit of %d: raise max_hosts or narrow the scope",
			stats.Hosts, e.opts.MaxHosts)
	}
	known, err := e.knownServices(ctx, scan.TargetID)
	if err != nil {
		return stats, err
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
				snaps, err := e.observe(ctx, sc, host, candidates[host], known[host])
				select {
				case results <- outcome{snaps: snaps, err: err}:
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
		stats.NewHosts += created[model.KindHost]
		stats.NewServices += created[model.KindService]
		for _, snap := range batch {
			if snap.Kind == model.KindService {
				stats.Services++
				stats.ServiceStates[snap.State]++
			} else {
				stats.States[snap.State]++
				done++
			}
		}
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
			batch = append(batch, res.snaps...)
			if len(batch) >= batchSize {
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

// knownServices maps each host to the endpoints on which a service has been
// recorded for it before. Like known hosts they are examined again whatever
// the configuration says, so that a service going away is noticed.
func (e *Engine) knownServices(ctx context.Context, targetID int64) (map[string][]Endpoint, error) {
	if e.prober == nil {
		return nil, nil
	}
	keys, err := e.store.AssetKeys(ctx, targetID, model.KindService)
	if err != nil {
		return nil, err
	}
	known := make(map[string][]Endpoint)
	for _, key := range keys {
		if scheme, host, port, ok := model.ParseServiceKey(key); ok {
			known[host] = append(known[host], Endpoint{Scheme: scheme, Port: port})
		}
	}
	return known, nil
}

// observe examines one host and turns the result into snapshots: one for
// the host and one for each service on it. The only errors it returns are
// fatal to the scan; a failed lookup or an unreachable service is recorded
// as the state of the asset instead.
func (e *Engine) observe(ctx context.Context, sc *scope.Scope, host string, sources []string, known []Endpoint) ([]storage.Snapshot, error) {
	obs := model.HostObservation{Host: host}
	state := model.StateDiscovered
	var addrs []netip.Addr

	if e.opts.Profile != model.ProfilePassive {
		var err error
		obs.DNS, state, addrs, err = e.resolveHost(ctx, sc, host)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil {
			e.log.Warn("lookup failed", "host", host, "err", err)
		}
	}

	data, err := json.Marshal(obs)
	if err != nil {
		return nil, fmt.Errorf("engine: encode observation of %s: %w", host, err)
	}
	layers := fingerprint.Host(obs)

	snaps := []storage.Snapshot{{
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
	}}
	if e.prober == nil {
		return snaps, nil
	}

	services, err := e.observeServices(ctx, sc, host, state, addrs, known)
	if err != nil {
		return nil, err
	}
	return append(snaps, services...), nil
}

// resolveHost looks a host up and classifies it. An observation is recorded
// in full or not at all: if any part of it could not be determined the host
// is reported as StateError without data, because a partial record would
// later be mistaken for a change.
func (e *Engine) resolveHost(ctx context.Context, sc *scope.Scope, host string) (*model.DNS, model.State, []netip.Addr, error) {
	res, err := e.resolver.Lookup(ctx, host)
	if err != nil {
		return nil, model.StateError, nil, err
	}
	dns := &model.DNS{
		Rcode: res.Rcode,
		CNAME: res.CNAME,
		A:     addrStrings(res.A),
		AAAA:  addrStrings(res.AAAA),
	}
	addrs := slices.Concat(res.A, res.AAAA)

	if sc.IsRoot(host) {
		// Delegation is a property of the zone, so it is tracked at the
		// roots only. A root is also never a wildcard candidate.
		if dns.NS, err = e.resolver.NS(ctx, host); err != nil {
			return nil, model.StateError, nil, err
		}
		if res.Resolved() {
			return dns, model.StateLive, addrs, nil
		}
		return dns, model.StateUnresolved, nil, nil
	}

	if !res.Resolved() {
		return dns, model.StateUnresolved, nil, nil
	}

	_, parent, _ := strings.Cut(host, ".")
	wildcard, err := e.resolver.Wildcard(ctx, parent)
	if err != nil {
		return nil, model.StateError, nil, fmt.Errorf("wildcard probe of %s: %w", parent, err)
	}
	if wildcard.Matches(res) {
		return dns, model.StateWildcard, addrs, nil
	}
	return dns, model.StateLive, addrs, nil
}

// observeServices examines the services of one host. On a host that
// resolves, every configured endpoint is tried, and an endpoint only turns
// into an asset once a service answers there. From then on it is reported
// in every scan, including the ones in which it cannot be reached.
func (e *Engine) observeServices(ctx context.Context, sc *scope.Scope, host string, state model.State, addrs []netip.Addr, known []Endpoint) ([]storage.Snapshot, error) {
	resolves := state == model.StateLive || state == model.StateWildcard

	endpoints := slices.Clone(known)
	if resolves {
		for _, ep := range e.opts.Endpoints {
			if !slices.Contains(known, ep) {
				endpoints = append(endpoints, ep)
			}
		}
	}

	var snaps []storage.Snapshot
	for _, ep := range endpoints {
		isKnown := slices.Contains(known, ep)

		res := probe.Result{
			State:       model.StateError,
			Observation: model.ServiceObservation{URL: model.ServiceKey(ep.Scheme, host, ep.Port)},
		}
		switch {
		case resolves:
			var err error
			res, err = e.prober.Service(ctx, probe.Target{
				Scheme:  ep.Scheme,
				Host:    host,
				Port:    ep.Port,
				Addrs:   addrs,
				Known:   isKnown,
				InScope: sc.Contains,
			})
			if err != nil {
				return nil, err
			}
			e.log.Debug("probed", "service", res.Observation.URL, "state", res.State, "reason", res.Observation.Error)
			if res.State != model.StateLive && !isKnown {
				continue
			}
		case state == model.StateUnresolved:
			res.State, res.Observation.Error = model.StateUnreachable, reasonUnresolved
		default:
			res.Observation.Error = reasonLookupFailed
		}

		snap, err := e.serviceSnapshot(host, res)
		if err != nil {
			return nil, err
		}
		snaps = append(snaps, snap)
	}
	return snaps, nil
}

func (e *Engine) serviceSnapshot(host string, res probe.Result) (storage.Snapshot, error) {
	obs := res.Observation
	data, err := json.Marshal(obs)
	if err != nil {
		return storage.Snapshot{}, fmt.Errorf("engine: encode observation of %s: %w", obs.URL, err)
	}
	layers := fingerprint.Service(obs, res.Leaf())

	snap := storage.Snapshot{
		Kind:        model.KindService,
		Key:         obs.URL,
		Host:        host,
		State:       res.State,
		FP:          layers.Composite(),
		FPTLS:       layers.TLS,
		FPHeaders:   layers.Headers,
		FPRedirect:  layers.Redirect,
		FPDOM:       layers.DOM,
		FaviconMMH3: obs.Favicon,
		Certs:       res.Certs,
		Data:        data,
		ObservedAt:  e.now(),
		Seen:        res.State == model.StateLive,
	}
	if obs.Page != nil {
		snap.DOMSimHash = obs.Page.SimHash
	}
	if snap.Seen {
		snap.Sources = []string{sourceProbe}
	}
	return snap, nil
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
