package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Dani4x2y/driftrecon/internal/collector"
	"github.com/Dani4x2y/driftrecon/internal/collector/resolve"
	"github.com/Dani4x2y/driftrecon/internal/dnstest"
	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/scope"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type fakeSource struct {
	name  string
	names map[string][]string
	err   error
	hook  func()
	calls atomic.Int32
}

func (f *fakeSource) Name() string {
	return f.name
}

func (f *fakeSource) Enumerate(_ context.Context, domain string) ([]string, error) {
	f.calls.Add(1)
	if f.hook != nil {
		f.hook()
	}
	return f.names[domain], f.err
}

type fixture struct {
	t      *testing.T
	store  *storage.Store
	target *storage.Target
	zone   *dnstest.Zone
	dns    *dnstest.Server
	clock  time.Time
}

func newFixture(t *testing.T, rules scope.Rules, records ...string) *fixture {
	t.Helper()

	store, err := storage.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	sc, err := scope.New(rules)
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.CreateTarget(t.Context(), "acme", sc.Rules(), t0)
	if err != nil {
		t.Fatal(err)
	}

	zone := dnstest.NewZone(records...)
	return &fixture{t: t, store: store, target: target, zone: zone, dns: dnstest.Start(t, zone), clock: t0}
}

func (f *fixture) engine(profile model.Profile, opts Options, sources ...collector.Source) *Engine {
	f.t.Helper()

	resolver, err := resolve.New(resolve.Options{
		Servers:  []string{f.dns.Addr},
		Timeout:  2 * time.Second,
		Attempts: 2,
	})
	if err != nil {
		f.t.Fatal(err)
	}

	opts.Profile = profile
	if opts.Concurrency == 0 {
		opts.Concurrency = 4
	}
	if opts.MaxHosts == 0 {
		opts.MaxHosts = 100
	}
	opts.Now = func() time.Time { return f.clock }

	e, err := New(f.store, sources, resolver, opts)
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f *fixture) scan(e *Engine) *storage.Scan {
	f.t.Helper()
	scan, err := e.Scan(f.t.Context(), f.target)
	if err != nil {
		f.t.Fatalf("scan failed: %v", err)
	}
	if scan.Status != storage.ScanCompleted {
		f.t.Fatalf("scan status = %s, want completed", scan.Status)
	}
	return scan
}

func (f *fixture) snapshots(scan *storage.Scan) map[string]storage.AssetSnapshot {
	f.t.Helper()
	snaps, err := f.store.Snapshots(f.t.Context(), scan.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	out := make(map[string]storage.AssetSnapshot, len(snaps))
	for _, s := range snaps {
		out[s.Key] = s
	}
	return out
}

func observation(t *testing.T, snap storage.AssetSnapshot) model.HostObservation {
	t.Helper()
	var obs model.HostObservation
	if err := json.Unmarshal(snap.Data, &obs); err != nil {
		t.Fatal(err)
	}
	return obs
}

func source(name, root string, names ...string) *fakeSource {
	return &fakeSource{name: name, names: map[string][]string{root: names}}
}

func TestScanClassifiesHosts(t *testing.T) {
	f := newFixture(t,
		scope.Rules{Roots: []string{"example.test"}, Exclude: []string{"vpn.example.test"}},
		"example.test. 60 IN A 192.0.2.1",
		"example.test. 60 IN NS ns2.dns.test.",
		"example.test. 60 IN NS ns1.dns.test.",
		"www.example.test. 60 IN A 192.0.2.10",
		"www.example.test. 60 IN AAAA 2001:db8::10",
		"shop.example.test. 60 IN CNAME edge.cdn.test.",
		"edge.cdn.test. 60 IN A 198.51.100.7",
		"old.example.test. 60 IN CNAME gone.hosting.test.",
		"wild.example.test. 60 IN A 192.0.2.1",
		"*.wild.example.test. 60 IN A 192.0.2.99",
		"vpn.example.test. 60 IN A 192.0.2.66",
	)
	f.zone.Fail("broken.example.test", dns.RcodeServerFailure)

	src := source("crtsh", "example.test",
		"www.example.test",
		"*.example.test",
		"SHOP.Example.Test.",
		"old.example.test",
		"ghost.example.test",
		"foo.wild.example.test",
		"broken.example.test",
		"vpn.example.test",
		"www.other.test",
		"admin@example.test",
		"Example Org",
		"www.example.test",
	)
	scan := f.scan(f.engine(model.ProfileStandard, Options{}, src))
	snaps := f.snapshots(scan)

	want := map[string]model.State{
		"example.test":          model.StateLive,
		"www.example.test":      model.StateLive,
		"shop.example.test":     model.StateLive,
		"old.example.test":      model.StateUnresolved,
		"ghost.example.test":    model.StateUnresolved,
		"foo.wild.example.test": model.StateWildcard,
		"broken.example.test":   model.StateError,
	}
	got := make(map[string]model.State, len(snaps))
	for host, snap := range snaps {
		got[host] = snap.State
	}
	if !maps.Equal(got, want) {
		t.Fatalf("states = %v\nwant     %v", got, want)
	}

	if f.dns.Queried("vpn.example.test") {
		t.Error("an excluded host was resolved")
	}
	if f.dns.Queried("www.other.test") {
		t.Error("a host outside the roots was resolved")
	}

	root := observation(t, snaps["example.test"])
	if want := []string{"ns1.dns.test", "ns2.dns.test"}; !slices.Equal(root.DNS.NS, want) {
		t.Errorf("root NS = %v, want %v", root.DNS.NS, want)
	}
	if want := []string{"crtsh"}; !slices.Equal(snaps["example.test"].Sources, want) {
		t.Errorf("root sources = %v, want %v: a wildcard name stands for its parent", snaps["example.test"].Sources, want)
	}

	www := observation(t, snaps["www.example.test"])
	if !slices.Equal(www.DNS.A, []string{"192.0.2.10"}) || !slices.Equal(www.DNS.AAAA, []string{"2001:db8::10"}) || www.DNS.NS != nil {
		t.Errorf("www = %+v", www.DNS)
	}

	shop := observation(t, snaps["shop.example.test"])
	if !slices.Equal(shop.DNS.CNAME, []string{"edge.cdn.test"}) || !slices.Equal(shop.DNS.A, []string{"198.51.100.7"}) {
		t.Errorf("shop = %+v", shop.DNS)
	}

	old := observation(t, snaps["old.example.test"])
	if old.DNS.Rcode != "NXDOMAIN" || !slices.Equal(old.DNS.CNAME, []string{"gone.hosting.test"}) {
		t.Errorf("old = %+v, want a dangling alias", old.DNS)
	}

	broken := snaps["broken.example.test"]
	if observation(t, broken).DNS != nil || broken.FPDNS != "" {
		t.Errorf("a failed lookup must not leave partial data: %s", broken.Data)
	}
	for host, snap := range snaps {
		if host != "broken.example.test" && snap.FPDNS == "" {
			t.Errorf("%s has no dns fingerprint", host)
		}
		if snap.FP == "" {
			t.Errorf("%s has no composite fingerprint", host)
		}
	}

	stats := scan.Stats
	if stats.Hosts != 7 || stats.NewAssets != 7 {
		t.Errorf("hosts = %d, new = %d, want 7 and 7", stats.Hosts, stats.NewAssets)
	}
	wantStates := map[model.State]int{
		model.StateLive:       3,
		model.StateUnresolved: 2,
		model.StateWildcard:   1,
		model.StateError:      1,
	}
	if !maps.Equal(stats.States, wantStates) {
		t.Errorf("state counts = %v, want %v", stats.States, wantStates)
	}
	wantSources := []model.SourceStat{{Source: "crtsh", Domain: "example.test", Names: 7}}
	if !slices.Equal(stats.Sources, wantSources) {
		t.Errorf("source stats = %+v, want %+v", stats.Sources, wantSources)
	}
}

func TestPassiveScanSendsNoQueries(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "www.example.test. 60 IN A 192.0.2.10")
	src := source("crtsh", "example.test", "www.example.test", "api.example.test")

	e, err := New(f.store, []collector.Source{src}, nil, Options{
		Profile:     model.ProfilePassive,
		Concurrency: 2,
		MaxHosts:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := f.scan(e)

	if n := f.dns.Queries(); n != 0 {
		t.Errorf("a passive scan sent %d DNS queries", n)
	}
	snaps := f.snapshots(scan)
	if len(snaps) != 3 {
		t.Fatalf("hosts = %d, want the root and two names", len(snaps))
	}
	for host, snap := range snaps {
		if snap.State != model.StateDiscovered || observation(t, snap).DNS != nil {
			t.Errorf("%s: state = %s, data = %s", host, snap.State, snap.Data)
		}
	}
	if scan.Profile != model.ProfilePassive {
		t.Errorf("profile = %s", scan.Profile)
	}
}

func TestKnownHostsSurviveSourceOutage(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}},
		"example.test. 60 IN A 192.0.2.1",
		"www.example.test. 60 IN A 192.0.2.10",
		"api.example.test. 60 IN A 192.0.2.20",
	)
	src := source("crtsh", "example.test", "www.example.test", "api.example.test")
	e := f.engine(model.ProfileStandard, Options{}, src)

	first := f.snapshots(f.scan(e))

	f.clock = t0.Add(24 * time.Hour)
	src.names = nil
	src.err = errors.New("service unavailable")
	f.zone.Remove("api.example.test")

	scan := f.scan(e)
	second := f.snapshots(scan)

	if len(second) != 3 || scan.Stats.Hosts != 3 || scan.Stats.NewAssets != 0 {
		t.Fatalf("second scan covered %d hosts (%d new), want the same 3", len(second), scan.Stats.NewAssets)
	}
	if got := scan.Stats.Sources; len(got) != 1 || got[0].Error == "" || got[0].Names != 0 {
		t.Errorf("source stats = %+v, want the outage on record", got)
	}

	www := second["www.example.test"]
	if www.State != model.StateLive || www.FP != first["www.example.test"].FP {
		t.Errorf("unchanged host: state = %s, fingerprint changed = %v", www.State, www.FP != first["www.example.test"].FP)
	}
	if !www.LastSeenAt.Equal(f.clock) {
		t.Errorf("last seen = %v, want %v: a resolving host counts as seen", www.LastSeenAt, f.clock)
	}
	if want := []string{"crtsh"}; !slices.Equal(www.Sources, want) {
		t.Errorf("sources = %v, want %v to be remembered", www.Sources, want)
	}

	api := second["api.example.test"]
	if api.State != model.StateUnresolved || api.FP == first["api.example.test"].FP {
		t.Errorf("removed host: state = %s, fingerprint changed = %v", api.State, api.FP != first["api.example.test"].FP)
	}
	if !api.LastSeenAt.Equal(t0) {
		t.Errorf("last seen = %v, want %v: nothing confirmed the host this time", api.LastSeenAt, t0)
	}
}

func TestScanCountsNewAssets(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}},
		"www.example.test. 60 IN A 192.0.2.10",
		"staging.example.test. 60 IN A 192.0.2.30",
	)
	src := source("crtsh", "example.test", "www.example.test")
	e := f.engine(model.ProfileStandard, Options{}, src)
	f.scan(e)

	f.clock = t0.Add(time.Hour)
	src.names["example.test"] = []string{"www.example.test", "staging.example.test"}
	scan := f.scan(e)

	if scan.Stats.NewAssets != 1 {
		t.Errorf("new assets = %d, want 1", scan.Stats.NewAssets)
	}
	staging := f.snapshots(scan)["staging.example.test"]
	if staging.State != model.StateLive || !staging.FirstSeenAt.Equal(f.clock) {
		t.Errorf("staging = %s first seen %v", staging.State, staging.FirstSeenAt)
	}
}

func TestMultipleRoots(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test", "corp.test"}},
		"www.example.test. 60 IN A 192.0.2.10",
		"mail.corp.test. 60 IN A 192.0.2.40",
	)
	src := &fakeSource{name: "crtsh", names: map[string][]string{
		"example.test": {"www.example.test", "mail.corp.test"},
		"corp.test":    {"mail.corp.test"},
	}}
	other := source("certspotter", "corp.test", "mail.corp.test", "intranet.corp.test")

	scan := f.scan(f.engine(model.ProfileStandard, Options{}, src, other))
	snaps := f.snapshots(scan)

	if n := src.calls.Load(); n != 2 {
		t.Errorf("source queried %d times, want once per root", n)
	}
	hosts := slices.Sorted(maps.Keys(snaps))
	want := []string{"corp.test", "example.test", "intranet.corp.test", "mail.corp.test", "www.example.test"}
	if !slices.Equal(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
	if want := []string{"certspotter", "crtsh"}; !slices.Equal(snaps["mail.corp.test"].Sources, want) {
		t.Errorf("sources = %v, want %v without duplicates", snaps["mail.corp.test"].Sources, want)
	}
	if len(scan.Stats.Sources) != 4 {
		t.Errorf("source stats = %+v, want one entry per source and root", scan.Stats.Sources)
	}
}

func TestPartialSourceResultsAreUsed(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}})
	flaky := source("certspotter", "example.test", "a.example.test")
	flaky.err = errors.New("rate limited")
	steady := source("crtsh", "example.test", "b.example.test")

	scan := f.scan(f.engine(model.ProfileStandard, Options{}, flaky, steady))

	hosts := slices.Sorted(maps.Keys(f.snapshots(scan)))
	if want := []string{"a.example.test", "b.example.test", "example.test"}; !slices.Equal(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
	want := []model.SourceStat{
		{Source: "certspotter", Domain: "example.test", Names: 1, Error: "rate limited"},
		{Source: "crtsh", Domain: "example.test", Names: 1},
	}
	if !slices.Equal(scan.Stats.Sources, want) {
		t.Errorf("source stats = %+v, want %+v", scan.Stats.Sources, want)
	}
}

func TestMaxHostsStopsBeforeAnyLookup(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}})
	src := source("crtsh", "example.test", "a.example.test", "b.example.test", "c.example.test")

	scan, err := f.engine(model.ProfileStandard, Options{MaxHosts: 3}, src).Scan(t.Context(), f.target)
	if err == nil {
		t.Fatal("a scan over the host limit must fail")
	}
	if scan == nil || scan.Status != storage.ScanFailed || !strings.Contains(scan.Stats.Reason, "limit of 3") {
		t.Fatalf("scan = %+v", scan)
	}
	if n := f.dns.Queries(); n != 0 {
		t.Errorf("%d queries were sent before the limit was enforced", n)
	}
	if len(f.snapshots(scan)) != 0 {
		t.Error("a failed scan stored snapshots")
	}
}

func TestInterruptedScanIsAborted(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "www.example.test. 60 IN A 192.0.2.10")
	ctx, cancel := context.WithCancel(t.Context())
	src := source("crtsh", "example.test", "www.example.test")
	src.hook = cancel

	scan, err := f.engine(model.ProfileStandard, Options{}, src).Scan(ctx, f.target)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if scan == nil || scan.Status != storage.ScanAborted || scan.Stats.Reason != "interrupted" {
		t.Fatalf("scan = %+v", scan)
	}

	stored, err := f.store.GetScan(t.Context(), f.target.ID, scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != storage.ScanAborted || stored.FinishedAt.IsZero() {
		t.Errorf("stored scan = %+v, want it closed as aborted", stored)
	}
	if _, err := f.store.LatestScan(t.Context(), f.target.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("an aborted scan must not become the baseline: err = %v", err)
	}
}

func TestScanTimeLimit(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}})
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	src := source("crtsh", "example.test", "www.example.test")
	src.hook = func() { <-ctx.Done() }

	scan, err := f.engine(model.ProfileStandard, Options{}, src).Scan(ctx, f.target)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if scan == nil || scan.Status != storage.ScanAborted || scan.Stats.Reason != "time limit reached" {
		t.Fatalf("scan = %+v", scan)
	}
}

func TestLargeScanIsWrittenInBatches(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "example.test. 60 IN A 192.0.2.1")
	names := make([]string, 2*batchSize+37)
	for i := range names {
		names[i] = fmt.Sprintf("h%03d.example.test", i)
		if i%3 == 0 {
			f.zone.Add(fmt.Sprintf("%s. 60 IN A 192.0.2.%d", names[i], 1+i%250))
		}
	}
	src := source("crtsh", "example.test", names...)

	scan := f.scan(f.engine(model.ProfileStandard, Options{Concurrency: 16, MaxHosts: 1000}, src))

	want := len(names) + 1
	if got := len(f.snapshots(scan)); got != want {
		t.Errorf("snapshots = %d, want %d", got, want)
	}
	total := 0
	for _, n := range scan.Stats.States {
		total += n
	}
	if total != want || scan.Stats.NewAssets != want {
		t.Errorf("stats = %+v, want %d hosts counted", scan.Stats, want)
	}
	if live := scan.Stats.States[model.StateLive]; live != (len(names)+2)/3+1 {
		t.Errorf("live = %d, want %d", live, (len(names)+2)/3+1)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}})
	resolver, err := resolve.New(resolve.Options{Servers: []string{f.dns.Addr}})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		resolver *resolve.Resolver
		opts     Options
	}{
		"unknown profile":     {resolver, Options{Profile: "aggressive", Concurrency: 1, MaxHosts: 1}},
		"missing resolver":    {nil, Options{Profile: model.ProfileStandard, Concurrency: 1, MaxHosts: 1}},
		"zero concurrency":    {resolver, Options{Profile: model.ProfileStandard, MaxHosts: 1}},
		"zero host limit":     {resolver, Options{Profile: model.ProfileStandard, Concurrency: 1}},
		"negative host limit": {resolver, Options{Profile: model.ProfilePassive, Concurrency: 1, MaxHosts: -1}},
	}
	for name, tc := range cases {
		if _, err := New(f.store, nil, tc.resolver, tc.opts); err == nil {
			t.Errorf("%s: New succeeded, want error", name)
		}
	}
}
