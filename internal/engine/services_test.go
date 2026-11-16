package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Dani4x2y/driftrecon/internal/collector"
	"github.com/Dani4x2y/driftrecon/internal/collector/probe"
	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/scope"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

// web is an HTTP server on the loopback interface that serves every
// hostname pointed at it and counts the requests per hostname.
type web struct {
	srv  *httptest.Server
	port uint16

	mu   sync.Mutex
	hits map[string]int
}

func serveWeb(t *testing.T, secure bool, handler http.HandlerFunc) *web {
	t.Helper()
	w := &web{hits: make(map[string]int)}
	w.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		w.mu.Lock()
		w.hits[host]++
		w.mu.Unlock()
		handler(rw, r)
	}))
	if secure {
		w.srv.StartTLS()
	} else {
		w.srv.Start()
	}
	t.Cleanup(w.srv.Close)
	w.port = uint16(w.srv.Listener.Addr().(*net.TCPAddr).Port)
	return w
}

func (w *web) requests() map[string]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return maps.Clone(w.hits)
}

func (w *web) endpoint() Endpoint {
	if w.srv.TLS != nil {
		return Endpoint{Scheme: "https", Port: w.port}
	}
	return Endpoint{Scheme: "http", Port: w.port}
}

func (w *web) key(host string) string {
	ep := w.endpoint()
	return model.ServiceKey(ep.Scheme, host, ep.Port)
}

// loopbackProber returns a prober that may talk to the test servers and
// does not pace itself.
func loopbackProber(t *testing.T) *probe.Prober {
	t.Helper()
	p, err := probe.New(probe.Options{
		UserAgent:    "driftrecon-test",
		Timeout:      3 * time.Second,
		HostRate:     10000,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func serviceObservation(t *testing.T, snap storage.AssetSnapshot) model.ServiceObservation {
	t.Helper()
	var obs model.ServiceObservation
	if err := json.Unmarshal(snap.Data, &obs); err != nil {
		t.Fatal(err)
	}
	return obs
}

func servicesOf(snaps map[string]storage.AssetSnapshot) []string {
	var keys []string
	for key, snap := range snaps {
		if snap.Kind == model.KindService {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

const welcomePage = `<html><head><title>Welcome</title></head><body>
<form action="/login" method="post"><input name="user"><input type="password" name="pass"></form>
</body></html>`

// site answers for two virtual hosts: a web application on www and an API
// that knows no front page on api.
func site(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.Host)
	switch {
	case host == "api.example.test":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"not found"}`)
	case r.URL.Path == "/":
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, welcomePage)
	default:
		http.NotFound(w, r)
	}
}

func TestScanProbesServices(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}},
		"www.example.test. 60 IN A 127.0.0.1",
		"api.example.test. 60 IN A 127.0.0.1",
	)
	plain, secure := serveWeb(t, false, site), serveWeb(t, true, site)
	f.prober = loopbackProber(t)
	src := source("crtsh", "example.test", "www.example.test", "api.example.test", "old.example.test")

	scan := f.scan(f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint(), secure.endpoint()}}, src))
	snaps := f.snapshots(scan)

	wantServices := []string{
		plain.key("api.example.test"), plain.key("www.example.test"),
		secure.key("api.example.test"), secure.key("www.example.test"),
	}
	slices.Sort(wantServices)
	if got := servicesOf(snaps); !slices.Equal(got, wantServices) {
		t.Fatalf("services = %v\nwant       %v", got, wantServices)
	}

	stats := scan.Stats
	if stats.Hosts != 4 || stats.NewHosts != 4 || stats.Services != 4 || stats.NewServices != 4 {
		t.Errorf("stats = %+v, want 4 new hosts and 4 new services", stats)
	}
	if want := map[model.State]int{model.StateLive: 4}; !maps.Equal(stats.ServiceStates, want) {
		t.Errorf("service states = %v, want %v", stats.ServiceStates, want)
	}
	if want := map[model.State]int{model.StateLive: 2, model.StateUnresolved: 2}; !maps.Equal(stats.States, want) {
		t.Errorf("host states = %v, want %v", stats.States, want)
	}

	www := snaps[plain.key("www.example.test")]
	if www.State != model.StateLive || www.Host != "www.example.test" || !slices.Equal(www.Sources, []string{sourceProbe}) {
		t.Errorf("www over http = %+v", www)
	}
	if www.FP == "" || www.FPHeaders == "" || www.FPRedirect == "" || www.FPDOM == "" || www.DOMSimHash == nil {
		t.Errorf("www over http lacks a layer: %+v", www)
	}
	if www.FPTLS != "" || www.FPDNS != "" || www.CertSHA256 != "" {
		t.Errorf("www over http has layers it cannot have: %+v", www)
	}
	if !www.FirstSeenAt.Equal(f.clock) || !www.LastSeenAt.Equal(f.clock) {
		t.Errorf("www over http seen %v to %v, want %v", www.FirstSeenAt, www.LastSeenAt, f.clock)
	}
	obs := serviceObservation(t, www)
	if obs.URL != www.Key || !slices.Equal(obs.Hops, []model.Hop{{Status: 200}}) || obs.Page == nil ||
		obs.Page.Title != "Welcome" || len(obs.Page.Forms) != 1 || !obs.Page.Forms[0].HasPassword() {
		t.Errorf("www observation = %+v", obs)
	}
	if obs.Headers.Values["server"] != "nginx" {
		t.Errorf("server = %q", obs.Headers.Values["server"])
	}

	wwwTLS := snaps[secure.key("www.example.test")]
	if wwwTLS.FPTLS == "" || wwwTLS.CertSHA256 == "" {
		t.Fatalf("www over https = %+v, want a tls layer and a certificate", wwwTLS)
	}
	tlsObs := serviceObservation(t, wwwTLS)
	if tlsObs.TLS == nil || !slices.Equal(tlsObs.TLS.Chain, []string{wwwTLS.CertSHA256}) ||
		!slices.Equal(tlsObs.TLS.Issues, []string{model.IssueHostnameMismatch, model.IssueSelfSigned}) {
		t.Errorf("tls = %+v", tlsObs.TLS)
	}
	certs, err := f.store.Certificates(t.Context(), wwwTLS.CertSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if cert, ok := certs[wwwTLS.CertSHA256]; !ok || !cert.SelfSigned || cert.SPKISHA256 == "" || cert.NotAfter.IsZero() {
		t.Errorf("stored certificate = %+v", certs)
	}
	if wwwTLS.FPHeaders != www.FPHeaders || wwwTLS.FPDOM != www.FPDOM {
		t.Error("the same application behind http and https has different header or dom layers")
	}

	api := snaps[plain.key("api.example.test")]
	apiObs := serviceObservation(t, api)
	if !slices.Equal(apiObs.Hops, []model.Hop{{Status: 404}}) || apiObs.Page == nil || apiObs.Page.ContentType != "application/json" {
		t.Errorf("api observation = %+v", apiObs)
	}
	if api.DOMSimHash != nil || api.FPDOM == "" {
		t.Errorf("api = %+v, want its body compared by content", api)
	}
	if api.FP == www.FP || api.FPDOM == www.FPDOM || api.FPRedirect == www.FPRedirect {
		t.Error("two different services share a fingerprint")
	}

	// Hosts that do not resolve are never connected to.
	for _, w := range []*web{plain, secure} {
		hits := w.requests()
		if len(hits) != 2 || hits["www.example.test"] == 0 || hits["api.example.test"] == 0 {
			t.Errorf("requests = %v, want only the two resolving hosts", hits)
		}
	}
}

func TestEndpointBecomesAnAssetOnceItAnswers(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "www.example.test. 60 IN A 127.0.0.1")
	plain := serveWeb(t, false, site)
	f.prober = loopbackProber(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := Endpoint{Scheme: "https", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	ln.Close()

	src := source("crtsh", "example.test", "www.example.test")
	scan := f.scan(f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint(), closed}}, src))

	if got, want := servicesOf(f.snapshots(scan)), []string{plain.key("www.example.test")}; !slices.Equal(got, want) {
		t.Errorf("services = %v, want %v: nothing ever answered on the other port", got, want)
	}
	if scan.Stats.Services != 1 || scan.Stats.NewServices != 1 {
		t.Errorf("stats = %+v", scan.Stats)
	}
	keys, err := f.store.AssetKeys(t.Context(), f.target.ID, model.KindService)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("service assets = %v", keys)
	}
}

func TestKnownServiceIsReportedWhenItGoesAway(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "www.example.test. 60 IN A 127.0.0.1")
	plain := serveWeb(t, false, site)
	f.prober = loopbackProber(t)
	src := source("crtsh", "example.test", "www.example.test")
	e := f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint()}}, src)
	key := plain.key("www.example.test")

	first := f.snapshots(f.scan(e))[key]
	if first.State != model.StateLive {
		t.Fatalf("first scan: state = %s", first.State)
	}

	step := func(wantState model.State, wantReason string) storage.AssetSnapshot {
		t.Helper()
		f.clock = f.clock.Add(24 * time.Hour)
		scan := f.scan(e)
		snap, ok := f.snapshots(scan)[key]
		if !ok {
			t.Fatalf("the service vanished from the scan instead of being reported as %s", wantState)
		}
		obs := serviceObservation(t, snap)
		if snap.State != wantState || obs.Error != wantReason {
			t.Errorf("state = %s (%q), want %s (%q)", snap.State, obs.Error, wantState, wantReason)
		}
		if obs.Headers != nil || obs.Page != nil || snap.FPHeaders != "" || snap.FP == first.FP {
			t.Errorf("snapshot = %+v, want no stale data", snap)
		}
		if !snap.LastSeenAt.Equal(t0) {
			t.Errorf("last seen = %v, want %v: the service did not answer", snap.LastSeenAt, t0)
		}
		if want := map[model.State]int{wantState: 1}; !maps.Equal(scan.Stats.ServiceStates, want) || scan.Stats.NewServices != 0 {
			t.Errorf("stats = %+v, want %v and nothing new", scan.Stats, want)
		}
		return snap
	}

	plain.srv.Close()
	step(model.StateUnreachable, probe.ReasonConnect)

	f.zone.Remove("www.example.test")
	step(model.StateUnreachable, reasonUnresolved)

	f.zone.Fail("www.example.test", dns.RcodeServerFailure)
	step(model.StateError, reasonLookupFailed)
}

func TestServiceFingerprintFollowsTheService(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "www.example.test. 60 IN A 127.0.0.1")
	var redesigned atomic.Bool
	plain := serveWeb(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if redesigned.Load() {
			w.Header().Set("Server", "Apache")
			fmt.Fprint(w, `<html><body><main><h1>New</h1><table><tr><td>1</td></tr></table></main></body></html>`)
			return
		}
		w.Header().Set("Server", "nginx")
		fmt.Fprint(w, welcomePage)
	})
	f.prober = loopbackProber(t)
	src := source("crtsh", "example.test", "www.example.test")
	e := f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint()}}, src)
	key := plain.key("www.example.test")

	first := f.snapshots(f.scan(e))[key]

	f.clock = f.clock.Add(time.Hour)
	second := f.snapshots(f.scan(e))[key]
	if second.FP != first.FP || string(second.Data) != string(first.Data) {
		t.Errorf("an unchanged service produced a different observation:\n%s\n%s", first.Data, second.Data)
	}
	if obs := serviceObservation(t, second); len(obs.Volatile) != 0 {
		t.Errorf("volatile = %v on a static page", obs.Volatile)
	}

	redesigned.Store(true)
	f.clock = f.clock.Add(time.Hour)
	third := f.snapshots(f.scan(e))[key]
	if third.FP == first.FP || third.FPHeaders == first.FPHeaders || third.FPDOM == first.FPDOM {
		t.Errorf("a new server and page kept a layer: %+v", third)
	}
	if third.FPRedirect != first.FPRedirect {
		t.Error("the redirect layer changed although the service still answers 200")
	}
	if third.DOMSimHash == nil || *third.DOMSimHash == *first.DOMSimHash {
		t.Errorf("simhash = %v, want it to move with the structure", third.DOMSimHash)
	}
}

func TestRedirectsAreClassifiedByScope(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}, Exclude: []string{"vpn.example.test"}},
		"www.example.test. 60 IN A 127.0.0.1",
		"api.example.test. 60 IN A 127.0.0.1",
		"old.example.test. 60 IN A 127.0.0.1",
	)
	targets := map[string]string{
		"www.example.test": "https://sso.example.test/login",
		"api.example.test": "https://idp.example.org/",
		"old.example.test": "https://vpn.example.test/",
	}
	plain := serveWeb(t, false, func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		http.Redirect(w, r, targets[host], http.StatusFound)
	})
	f.prober = loopbackProber(t)
	src := source("crtsh", "example.test", "www.example.test", "api.example.test", "old.example.test")

	snaps := f.snapshots(f.scan(f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint()}}, src)))

	want := map[string]model.Relation{
		"www.example.test": model.RelInScope,
		"api.example.test": model.RelExternal,
		"old.example.test": model.RelExternal,
	}
	for host, relation := range want {
		obs := serviceObservation(t, snaps[plain.key(host)])
		if len(obs.Hops) != 1 || obs.Hops[0].Relation != relation {
			t.Errorf("%s: hops = %+v, want one %s redirect", host, obs.Hops, relation)
		}
	}
	// Each front page once per sample, and nothing a redirect points to.
	for host, n := range plain.requests() {
		if n != 2 {
			t.Errorf("%s received %d requests, want 2", host, n)
		}
	}
}

func TestWildcardHostsAreProbed(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}},
		"apps.example.test. 60 IN A 127.0.0.1",
		"*.apps.example.test. 60 IN A 127.0.0.1",
	)
	plain := serveWeb(t, false, site)
	f.prober = loopbackProber(t)
	src := source("crtsh", "example.test", "shop.apps.example.test")

	snaps := f.snapshots(f.scan(f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint()}}, src)))

	if got := snaps["shop.apps.example.test"].State; got != model.StateWildcard {
		t.Fatalf("host state = %s, want %s", got, model.StateWildcard)
	}
	// A name from a certificate is likely a real virtual host even when the
	// zone answers for every name.
	if snap, ok := snaps[plain.key("shop.apps.example.test")]; !ok || snap.State != model.StateLive {
		t.Errorf("service = %+v, want it examined", snap)
	}
}

func TestPassiveScanIgnoresTheProber(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "www.example.test. 60 IN A 127.0.0.1")
	plain := serveWeb(t, false, site)
	src := source("crtsh", "example.test", "www.example.test")

	e, err := New(f.store, []collector.Source{src}, nil, loopbackProber(t), Options{
		Profile:     model.ProfilePassive,
		Concurrency: 2,
		MaxHosts:    10,
		Endpoints:   []Endpoint{plain.endpoint()},
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := f.scan(e)

	if got := servicesOf(f.snapshots(scan)); len(got) != 0 {
		t.Errorf("services = %v", got)
	}
	if hits := plain.requests(); len(hits) != 0 || f.dns.Queries() != 0 {
		t.Errorf("a passive scan sent %v requests and %d queries", hits, f.dns.Queries())
	}
}

func TestServicesOnNonPublicAddressesAreNotProbed(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}},
		"www.example.test. 60 IN A 127.0.0.1",
		"intranet.example.test. 60 IN A 10.20.30.40",
	)
	plain := serveWeb(t, false, site)
	strict, err := probe.New(probe.Options{UserAgent: "driftrecon-test"})
	if err != nil {
		t.Fatal(err)
	}
	f.prober = strict
	src := source("crtsh", "example.test", "www.example.test", "intranet.example.test")

	scan := f.scan(f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint()}}, src))
	snaps := f.snapshots(scan)

	if got := servicesOf(snaps); len(got) != 0 {
		t.Errorf("services = %v, want none", got)
	}
	if hits := plain.requests(); len(hits) != 0 {
		t.Errorf("requests = %v, want no connection to a non-public address", hits)
	}
	// The name is still recorded with where it points: a public name that
	// resolves to a private address is a finding in itself.
	if got := snaps["intranet.example.test"].State; got != model.StateLive {
		t.Errorf("host state = %s", got)
	}
}

func TestScanInterruptedWhileProbing(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}}, "www.example.test. 60 IN A 127.0.0.1")
	ctx, cancel := context.WithCancel(t.Context())
	plain := serveWeb(t, false, func(_ http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	})
	f.prober = loopbackProber(t)
	src := source("crtsh", "example.test", "www.example.test")

	scan, err := f.engine(model.ProfileStandard, Options{Endpoints: []Endpoint{plain.endpoint()}}, src).Scan(ctx, f.target)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if scan == nil || scan.Status != storage.ScanAborted {
		t.Fatalf("scan = %+v, want it aborted", scan)
	}
}

func TestConfigHash(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}})
	loose := loopbackProber(t)
	strict, err := probe.New(probe.Options{UserAgent: "driftrecon-test"})
	if err != nil {
		t.Fatal(err)
	}
	web := []Endpoint{{Scheme: "http", Port: 80}, {Scheme: "https", Port: 443}}

	hash := func(profile model.Profile, prober *probe.Prober, endpoints ...Endpoint) string {
		f.prober = prober
		return f.engine(profile, Options{Endpoints: endpoints}).configHash()
	}
	plain := func(config string) string {
		sum := sha256.Sum256([]byte(config))
		return hex.EncodeToString(sum[:])
	}

	// Scans that stop at name resolution stay comparable with the ones
	// stored before services were probed at all.
	if got := hash(model.ProfileStandard, nil); got != plain("profile=standard") {
		t.Errorf("standard without probing = %s", got)
	}
	if got := hash(model.ProfileStandard, strict); got != plain("profile=standard") {
		t.Errorf("standard without endpoints = %s", got)
	}
	if got := hash(model.ProfilePassive, strict, web...); got != plain("profile=passive") {
		t.Errorf("passive = %s", got)
	}

	base := hash(model.ProfileStandard, strict, web...)
	if base == plain("profile=standard") {
		t.Error("probing services did not change the hash")
	}
	if got := hash(model.ProfileStandard, strict, web[1], web[0]); got != base {
		t.Error("the order of endpoints changed the hash")
	}
	if got := hash(model.ProfileStandard, strict, append(web, Endpoint{Scheme: "https", Port: 8443})...); got == base {
		t.Error("an extra endpoint kept the hash")
	}
	if got := hash(model.ProfileStandard, strict, web[0]); got == base {
		t.Error("a missing endpoint kept the hash")
	}
	if got := hash(model.ProfileStandard, loose, web...); got == base {
		t.Error("probing non-public addresses kept the hash")
	}
}

func TestNewValidatesEndpoints(t *testing.T) {
	f := newFixture(t, scope.Rules{Roots: []string{"example.test"}})
	f.prober = loopbackProber(t)

	cases := map[string][]Endpoint{
		"unknown scheme": {{Scheme: "ftp", Port: 21}},
		"missing scheme": {{Port: 80}},
		"port zero":      {{Scheme: "http"}},
		"port twice":     {{Scheme: "http", Port: 8080}, {Scheme: "https", Port: 443}, {Scheme: "https", Port: 8080}},
	}
	for name, endpoints := range cases {
		resolver := f.engine(model.ProfileStandard, Options{}).resolver
		_, err := New(f.store, nil, resolver, f.prober, Options{
			Profile:     model.ProfileStandard,
			Concurrency: 1,
			MaxHosts:    1,
			Endpoints:   endpoints,
		})
		if err == nil {
			t.Errorf("%s: New succeeded, want error", name)
		}
	}
}
