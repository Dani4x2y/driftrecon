package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/dnstest"
	"github.com/Dani4x2y/driftrecon/internal/fingerprint"
	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

var seedTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// seedServices stores a completed scan of a web host with its services for
// the named target, without touching the network.
func (e *env) seedServices(target string) {
	e.t.Helper()
	ctx := e.t.Context()

	store, err := storage.Open(ctx, e.db)
	if err != nil {
		e.t.Fatal(err)
	}
	defer store.Close()

	tgt, err := store.GetTarget(ctx, target)
	if err != nil {
		e.t.Fatal(err)
	}
	scan, err := store.BeginScan(ctx, tgt.ID, model.ProfileStandard, "cfg", 1, seedTime)
	if err != nil {
		e.t.Fatal(err)
	}

	host := func(name string, state model.State, dns *model.DNS, sources ...string) storage.Snapshot {
		obs := model.HostObservation{Host: name, DNS: dns}
		data, err := json.Marshal(obs)
		if err != nil {
			e.t.Fatal(err)
		}
		layers := fingerprint.Host(obs)
		return storage.Snapshot{
			Kind:       model.KindHost,
			Key:        name,
			Host:       name,
			State:      state,
			FP:         layers.Composite(),
			FPDNS:      layers.DNS,
			Data:       data,
			ObservedAt: seedTime,
			Sources:    sources,
			Seen:       true,
		}
	}
	service := func(obs model.ServiceObservation, hostname string, state model.State, certs ...model.Certificate) storage.Snapshot {
		data, err := json.Marshal(obs)
		if err != nil {
			e.t.Fatal(err)
		}
		var leaf *model.Certificate
		if len(certs) > 0 {
			leaf = &certs[0]
		}
		layers := fingerprint.Service(obs, leaf)
		snap := storage.Snapshot{
			Kind:        model.KindService,
			Key:         obs.URL,
			Host:        hostname,
			State:       state,
			FP:          layers.Composite(),
			FPTLS:       layers.TLS,
			FPHeaders:   layers.Headers,
			FPRedirect:  layers.Redirect,
			FPDOM:       layers.DOM,
			FaviconMMH3: obs.Favicon,
			Certs:       certs,
			Data:        data,
			ObservedAt:  seedTime,
			Seen:        state == model.StateLive,
		}
		if obs.Page != nil {
			snap.DOMSimHash = obs.Page.SimHash
		}
		return snap
	}

	leaf := model.Certificate{
		SHA256:     strings.Repeat("ab", 32),
		SubjectCN:  "www.example.com",
		IssuerCN:   "R11",
		IssuerOrg:  "Let's Encrypt",
		Serial:     "04d2",
		SANs:       []string{"example.com", "www.example.com"},
		SPKISHA256: strings.Repeat("cd", 32),
		NotBefore:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:   time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC),
		KeyAlg:     "ECDSA-P-256",
	}
	simhash := model.SimHash(0xb58b71ccd6ca55eb)
	favicon := int32(-1874651529)

	secure := model.ServiceObservation{
		URL: "https://www.example.com:443",
		TLS: &model.TLS{Version: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", ALPN: "h2", Chain: []string{leaf.SHA256}},
		Hops: []model.Hop{
			{Status: 302, Location: "https://www.example.com/login?next", Relation: model.RelSameOrigin},
			{Status: 200},
		},
		Headers: &model.Headers{
			Names: []string{"Server", "Date", "Content-Type", "Set-Cookie", "Strict-Transport-Security"},
			Values: map[string]string{
				"server":                    "nginx/1.24.0",
				"strict-transport-security": "max-age=31536000",
				"x-frame-options":           "DENY",
			},
			Cookies: []model.Cookie{{Name: "session", Flags: []string{"httponly", "secure"}}, {Name: "lang"}},
		},
		Page: &model.Page{
			ContentType: "text/html",
			Title:       "Sign in",
			Skeleton:    strings.Repeat("ef", 32),
			SimHash:     &simhash,
			Forms: []model.Form{{
				Method: "POST",
				Action: "/session",
				Fields: []model.FormField{{Type: "password", Name: "pass"}, {Type: "text", Name: "user"}},
			}},
			Scripts:    []string{"https://www.example.com/app.js", "https://cdn.example.org/lib.js"},
			BodySHA256: strings.Repeat("12", 32),
		},
		Favicon:  &favicon,
		Volatile: []string{"header:x-cache"},
	}
	plain := model.ServiceObservation{
		URL:     "http://www.example.com:80",
		Hops:    []model.Hop{{Status: 301, Location: "https://www.example.com/", Relation: model.RelSameHost}},
		Headers: &model.Headers{Names: []string{"Location", "Content-Length"}},
	}
	gone := model.ServiceObservation{URL: "https://old.example.com:443", Error: "host does not resolve"}

	_, err = store.SaveSnapshots(ctx, scan, []storage.Snapshot{
		host("www.example.com", model.StateLive, &model.DNS{
			Rcode: "NOERROR",
			CNAME: []string{"edge.cdn.example.net"},
			A:     []string{"198.51.100.1"},
		}, "certspotter", "crtsh"),
		host("old.example.com", model.StateUnresolved, &model.DNS{Rcode: "NXDOMAIN"}, "crtsh"),
		service(secure, "www.example.com", model.StateLive, leaf),
		service(plain, "www.example.com", model.StateLive),
		service(gone, "old.example.com", model.StateUnreachable),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	stats := model.ScanStats{Hosts: 2, Services: 3}
	if err := store.FinishScan(ctx, scan, storage.ScanCompleted, stats, seedTime.Add(time.Minute)); err != nil {
		e.t.Fatal(err)
	}
}

func TestAssetsListsServices(t *testing.T) {
	e := newEnv(t)
	e.mustRun("target", "add", "acme", "--root", "example.com", "--authorized")
	e.seedServices("acme")

	out := e.mustRun("assets", "acme")
	assertContains(t, out,
		"scan #1 of acme (standard, 2026-03-01 12:00 UTC): 2 of 2 hosts",
		"HOST STATE ADDRESSES CNAME SERVICES SOURCES FIRST SEEN",
		"www.example.com live 198.51.100.1 edge.cdn.example.net http 301, https 200 certspotter,crtsh 2026-03-01",
		"old.example.com unresolved https down crtsh 2026-03-01",
	)

	out = e.mustRun("assets", "acme", "--kind", "service")
	assertContains(t, out,
		"scan #1 of acme (standard, 2026-03-01 12:00 UTC): 3 of 3 services",
		"SERVICE STATE RESPONSE TITLE SERVER CERT EXPIRES FIRST SEEN",
		"https://old.example.com unreachable host does not resolve 2026-03-01",
		"http://www.example.com live 301 2026-03-01",
		"https://www.example.com live 302 > 200 Sign in nginx/1.24.0 2026-05-02 2026-03-01",
	)
	// Services follow the order of their hosts.
	if strings.Index(out, "https://old.example.com") > strings.Index(out, "http://www.example.com") {
		t.Errorf("services are not grouped by domain:\n%s", out)
	}

	out = e.mustRun("assets", "acme", "--kind", "service", "--state", "unreachable")
	assertContains(t, out, "1 of 3 services", "https://old.example.com")
	if strings.Contains(out, "www.example.com") {
		t.Errorf("the state filter let another service through:\n%s", out)
	}

	out = e.mustRun("assets", "acme", "--kind", "service", "--state", "error")
	if !strings.Contains(out, "0 of 3 services") || strings.Contains(out, "SERVICE") {
		t.Errorf("empty listing should have no table:\n%s", out)
	}

	for name, args := range map[string][]string{
		"host state for services": {"assets", "acme", "--kind", "service", "--state", "wildcard"},
		"service state for hosts": {"assets", "acme", "--state", "unreachable"},
		"unknown kind":            {"assets", "acme", "--kind", "port"},
	} {
		if out, err := e.run(args...); err == nil {
			t.Errorf("%s: accepted, output:\n%s", name, out)
		}
	}
}

func TestShow(t *testing.T) {
	e := newEnv(t)
	e.now = time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	e.mustRun("target", "add", "acme", "--root", "example.com", "--authorized")
	e.seedServices("acme")

	out := e.mustRun("show", "www.example.com")
	assertContains(t, out,
		"scan #1 of acme (standard, 2026-03-01 12:00 UTC)",

		"host www.example.com",
		"state live",
		"first seen 2026-03-01 12:00 UTC",
		"sources certspotter, crtsh",
		"dns NOERROR",
		"addresses 198.51.100.1",
		"cname edge.cdn.example.net",

		"service http://www.example.com",
		"response 301 > https://www.example.com/ (same-host)",
		"headers Location, Content-Length",

		"service https://www.example.com",
		"response 302 > https://www.example.com/login?next (same-origin)",
		"server nginx/1.24.0",
		"headers Server, Date, Content-Type, Set-Cookie, Strict-Transport-Security",
		"values strict-transport-security: max-age=31536000",
		"x-frame-options: DENY",
		"cookies session (httponly, secure), lang",
		"title Sign in",
		"content text/html, sha256 121212121212",
		"forms POST /session: password pass, text user",
		"scripts 2, also from cdn.example.org",
		"favicon mmh3 -1874651529",
		"tls TLS 1.3, TLS_AES_128_GCM_SHA256, alpn h2",
		"certificate www.example.com, issued by R11 (Let's Encrypt)",
		"valid 2026-02-01 to 2026-05-02 (44 days left)",
		"names: example.com, www.example.com",
		"key ECDSA-P-256, sha256 abababababab",
		"volatile header:x-cache",
		"simhash b58b71ccd6ca55eb",
	)
	host, plain, secure := strings.Index(out, "host www.example.com"), strings.Index(out, "service http://"), strings.Index(out, "service https://")
	if host > plain || plain > secure {
		t.Errorf("sections are out of order:\n%s", out)
	}
	if strings.Contains(out, "trust issues") {
		t.Errorf("a trusted certificate is shown with issues:\n%s", out)
	}

	for _, ref := range []string{"https://www.example.com", "https://WWW.Example.com:443/login?x=1"} {
		out = e.mustRun("show", ref)
		assertContains(t, out, "service https://www.example.com", "title Sign in")
		if strings.Contains(out, "host www.example.com") || strings.Contains(out, "service http://") {
			t.Errorf("show %s printed more than the one service:\n%s", ref, out)
		}
	}

	out = e.mustRun("show", "OLD.example.com.", "--scan", "1")
	assertContains(t, out,
		"host old.example.com",
		"state unresolved",
		"dns NXDOMAIN",
		"service https://old.example.com",
		"state unreachable (host does not resolve)",
	)
}

func TestShowRejectsWhatItCannotFind(t *testing.T) {
	e := newEnv(t)
	e.mustRun("target", "add", "acme", "--root", "example.com", "--authorized")
	e.mustRun("target", "add", "empty", "--root", "example.org", "--authorized")
	e.seedServices("acme")

	cases := map[string]struct {
		args []string
		want string
	}{
		"unknown host":        {[]string{"show", "nope.example.com"}, "not known to any target"},
		"unrecorded service":  {[]string{"show", "http://old.example.com"}, "is not part of scan #1"},
		"unrecorded port":     {[]string{"show", "https://www.example.com:8443"}, "is not part of scan #1"},
		"other target":        {[]string{"show", "www.example.com", "--target", "empty"}, "no completed scan"},
		"not a hostname":      {[]string{"show", "not a host"}, ""},
		"unsupported scheme":  {[]string{"show", "ftp://www.example.com"}, "not an http or https URL"},
		"invalid port":        {[]string{"show", "https://www.example.com:0"}, "invalid port"},
		"address":             {[]string{"show", "198.51.100.1"}, ""},
		"missing argument":    {[]string{"show"}, ""},
		"too many arguments":  {[]string{"show", "www.example.com", "old.example.com"}, ""},
		"unknown target flag": {[]string{"show", "www.example.com", "--target", "nope"}, "not found"},
	}
	for name, tc := range cases {
		out, err := e.run(tc.args...)
		if err == nil {
			t.Errorf("%s: accepted, output:\n%s", name, out)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}

	if _, err := e.run("show", "www.example.com", "--scan", "999"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown scan: err = %v, want ErrNotFound", err)
	}
}

func TestShowAsksWhichTargetIsMeant(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"acme", "beta"} {
		e.mustRun("target", "add", name, "--root", "example.com", "--authorized")
		e.seedServices(name)
	}

	_, err := e.run("show", "www.example.com")
	if err == nil || !strings.Contains(err.Error(), "acme, beta") || !strings.Contains(err.Error(), "--target") {
		t.Fatalf("err = %v, want the candidates and a hint at --target", err)
	}
	assertContains(t, e.mustRun("show", "www.example.com", "--target", "beta"), "of beta (standard", "host www.example.com")
}

func TestValidity(t *testing.T) {
	cert := model.Certificate{
		NotBefore: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC),
	}
	cases := map[time.Time]string{
		time.Date(2026, 1, 31, 23, 0, 0, 0, time.UTC): "not valid yet",
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC):   "90 days left",
		time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC):  "0 days left",
		time.Date(2026, 5, 2, 0, 0, 1, 0, time.UTC):   "expired 0 days ago",
		time.Date(2026, 5, 12, 6, 0, 0, 0, time.UTC):  "expired 10 days ago",
	}
	for now, want := range cases {
		if got := validity(cert, now); got != want {
			t.Errorf("validity at %s = %q, want %q", now.Format(time.RFC3339), got, want)
		}
	}
}

func TestParseAssetRef(t *testing.T) {
	cases := []struct {
		ref, host, service string
	}{
		{"www.example.com", "www.example.com", ""},
		{"WWW.Example.COM.", "www.example.com", ""},
		{"https://www.example.com", "www.example.com", "https://www.example.com:443"},
		{"http://www.example.com/", "www.example.com", "http://www.example.com:80"},
		{"https://www.example.com:8443/admin?x=1", "www.example.com", "https://www.example.com:8443"},
		{"HTTP://www.example.com:8080", "www.example.com", "http://www.example.com:8080"},
	}
	for _, tc := range cases {
		host, service, err := parseAssetRef(tc.ref)
		if err != nil || host != tc.host || service != tc.service {
			t.Errorf("parseAssetRef(%q) = %q, %q, %v, want %q, %q", tc.ref, host, service, err, tc.host, tc.service)
		}
	}

	for _, bad := range []string{"", "localhost", "192.0.2.1", "ftp://www.example.com", "https://", "https://www.example.com:99999", "https://192.0.2.1"} {
		if host, service, err := parseAssetRef(bad); err == nil {
			t.Errorf("parseAssetRef(%q) = %q, %q, want an error", bad, host, service)
		}
	}
}

func TestServiceLabels(t *testing.T) {
	hops := func(statuses ...int) model.ServiceObservation {
		var obs model.ServiceObservation
		for _, s := range statuses {
			obs.Hops = append(obs.Hops, model.Hop{Status: s})
		}
		return obs
	}
	cases := []struct {
		key   string
		state model.State
		obs   model.ServiceObservation
		label string
		url   string
	}{
		{"https://a.example.com:443", model.StateLive, hops(200), "https 200", "https://a.example.com"},
		{"http://a.example.com:80", model.StateLive, hops(301, 302, 404), "http 404", "http://a.example.com"},
		{"http://a.example.com:8080", model.StateLive, hops(200), "http:8080 200", "http://a.example.com:8080"},
		{"https://a.example.com:80", model.StateLive, hops(200), "https:80 200", "https://a.example.com:80"},
		{"https://a.example.com:443", model.StateUnreachable, model.ServiceObservation{Error: "timeout"}, "https down", "https://a.example.com"},
		{"https://a.example.com:443", model.StateError, model.ServiceObservation{Error: "no public address"}, "https ?", "https://a.example.com"},
		{"https://a.example.com:443", model.StateLive, model.ServiceObservation{Error: "malformed response"}, "https no http", "https://a.example.com"},
	}
	for _, tc := range cases {
		snap := storage.AssetSnapshot{Key: tc.key, State: tc.state}
		if got := serviceLabel(snap, tc.obs); got != tc.label {
			t.Errorf("serviceLabel(%s, %s) = %q, want %q", tc.key, tc.state, got, tc.label)
		}
		if got := displayURL(tc.key); got != tc.url {
			t.Errorf("displayURL(%s) = %q, want %q", tc.key, got, tc.url)
		}
	}

	if got := responseSummary(hops(301, 302, 200)); got != "301 > 302 > 200" {
		t.Errorf("responseSummary = %q", got)
	}
	if got := responseSummary(model.ServiceObservation{Error: "timeout"}); got != "timeout" {
		t.Errorf("responseSummary without hops = %q", got)
	}
}

func TestShorten(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
	}{
		{"", 10, ""},
		{"short", 10, "short"},
		{"exactly 10", 10, "exactly 10"},
		{"one more than", 12, "one more ..."},
		{"zażółć gęślą jaźń", 10, "zażółć ..."},
	}
	for _, tc := range cases {
		if got := shorten(tc.in, tc.limit); got != tc.want {
			t.Errorf("shorten(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
		}
	}
}

// TestScanWithServicesEndToEnd drives the real commands against a local CT
// endpoint, a local resolver and local web servers.
func TestScanWithServicesEndToEnd(t *testing.T) {
	resolver := dnstest.Start(t, dnstest.NewZone(
		"www.example.test. 60 IN A 127.0.0.1",
		"api.example.test. 60 IN A 127.0.0.1",
	))

	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"name_value":"www.example.test\napi.example.test"}]`)
	}))
	t.Cleanup(ct.Close)

	site := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.UserAgent(), "driftrecon/") {
			t.Errorf("user agent = %q, want the tool to identify itself", r.UserAgent())
		}
		host, _, _ := net.SplitHostPort(r.Host)
		switch {
		case host == "api.example.test":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"not found"}`)
		case r.URL.Path == "/":
			w.Header().Set("Server", "nginx")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<html><head><title>Welcome</title></head><body><h1>Hello</h1></body></html>`)
		default:
			http.NotFound(w, r)
		}
	})
	plain := httptest.NewServer(site)
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(site)
	t.Cleanup(secure.Close)
	plainPort := plain.Listener.Addr().(*net.TCPAddr).Port
	securePort := secure.Listener.Addr().(*net.TCPAddr).Port

	e := newEnvWithConfig(t, fmt.Sprintf(`
resolvers: ["%s"]
timeout: 2s
sources:
  crtsh:
    url: %s
  certspotter:
    enabled: false
probe:
  http_ports: [%d]
  https_ports: [%d]
  rate: 1000
  host_rate: 1000
  timeout: 3s
  allow_private: true
`, resolver.Addr, ct.URL, plainPort, securePort))
	e.mustRun("target", "add", "acme", "--root", "example.test", "--authorized")

	out := e.mustRun("scan", "acme")
	assertContains(t, out,
		"scan #1 of acme completed",
		"hosts: 3 in scope, 3 new",
		"services: 4 recorded, 4 new",
		"live 4",
	)

	wwwPlain := fmt.Sprintf("http://www.example.test:%d", plainPort)
	wwwSecure := fmt.Sprintf("https://www.example.test:%d", securePort)

	assertContains(t, e.mustRun("assets", "acme"),
		fmt.Sprintf("www.example.test live 127.0.0.1 http:%d 200, https:%d 200 crtsh", plainPort, securePort),
		fmt.Sprintf("api.example.test live 127.0.0.1 http:%d 404, https:%d 404 crtsh", plainPort, securePort),
	)

	out = e.mustRun("assets", "acme", "--kind", "service")
	assertContains(t, out,
		"4 of 4 services",
		wwwPlain+" live 200 Welcome nginx",
		wwwSecure+" live 200 Welcome nginx 2084-01-29",
		fmt.Sprintf("http://api.example.test:%d live 404", plainPort),
	)

	out = e.mustRun("show", "www.example.test")
	assertContains(t, out,
		"host www.example.test",
		"service "+wwwPlain,
		"service "+wwwSecure,
		"title Welcome",
		"server nginx",
		"response 200",
		"tls TLS 1.3",
		"self-signed",
		"trust issues hostname_mismatch, self_signed",
	)
	assertContains(t, e.mustRun("show", wwwPlain), "service "+wwwPlain, "content text/html, sha256")

	out = e.mustRun("scan", "acme")
	assertContains(t, out, "scan #2 of acme completed", "hosts: 3 in scope, 0 new", "services: 4 recorded, 0 new")

	out = e.mustRun("scan", "acme", "--profile", "passive")
	if strings.Contains(out, "services:") {
		t.Errorf("a passive scan reported services:\n%s", out)
	}
}

func TestScanWithoutPortsStopsAtResolution(t *testing.T) {
	resolver := dnstest.Start(t, dnstest.NewZone("www.example.test. 60 IN A 127.0.0.1"))
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"name_value":"www.example.test"}]`)
	}))
	t.Cleanup(ct.Close)

	e := newEnvWithConfig(t, fmt.Sprintf(`
resolvers: ["%s"]
sources:
  crtsh:
    url: %s
  certspotter:
    enabled: false
probe:
  http_ports: []
  https_ports: []
  allow_private: true
`, resolver.Addr, ct.URL))
	e.mustRun("target", "add", "acme", "--root", "example.test", "--authorized")

	out := e.mustRun("scan", "acme")
	assertContains(t, out, "scan #1 of acme completed", "hosts: 2 in scope, 2 new", "live 1")
	if strings.Contains(out, "services:") {
		t.Errorf("services were reported without any port to check:\n%s", out)
	}
}
