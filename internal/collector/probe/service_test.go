package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// route produces the response to the nth request for one path, counting
// from 1.
type route func(n int) string

func always(response string) route {
	return func(int) string { return response }
}

// site is a raw server that routes by request target and remembers what it
// was asked for. Unknown targets get a 404, and the "*" route, if present,
// answers them instead.
type site struct {
	*rawServer
	mu    sync.Mutex
	asked []string
}

func serveSite(t *testing.T, conf *tls.Config, routes map[string]route) *site {
	t.Helper()
	s := &site{}
	counts := make(map[string]int)
	s.rawServer = serveRaw(t, conf, func(w io.Writer, r *http.Request) {
		if r == nil {
			return
		}
		s.mu.Lock()
		s.asked = append(s.asked, r.RequestURI)
		counts[r.RequestURI]++
		n := counts[r.RequestURI]
		s.mu.Unlock()

		handler, ok := routes[r.RequestURI]
		if !ok {
			handler, ok = routes["*"]
		}
		if !ok {
			io.WriteString(w, response(404, nil, "not found"))
			return
		}
		io.WriteString(w, handler(n))
	})
	return s
}

func (s *site) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.asked)
}

func (s *site) target(scheme string) Target {
	return Target{Scheme: scheme, Host: testHost, Port: s.port, Addrs: loopback, InScope: inExampleScope}
}

// response renders an HTTP response with the given header lines.
func response(status int, headers []string, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	return b.String()
}

func htmlPage(body string) string {
	return response(200, []string{"Content-Type: text/html; charset=utf-8"}, body)
}

func redirect(location string) string {
	return response(302, []string{"Location: " + location}, "")
}

const ico = "\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00"

func probeService(t *testing.T, p *Prober, target Target) Result {
	t.Helper()
	res, err := p.Service(t.Context(), target)
	if err != nil {
		t.Fatalf("probe %s://%s:%d: %v", target.Scheme, target.Host, target.Port, err)
	}
	return res
}

func TestServiceObservesTheFrontPage(t *testing.T) {
	srv := serveSite(t, nil, map[string]route{
		"/": always(response(200, []string{
			"Server: nginx/1.24.0",
			"Content-Type: text/html; charset=utf-8",
			"Set-Cookie: session=c2VjcmV0; HttpOnly",
			"X-Frame-Options: DENY",
		}, `<html><head><title>Welcome</title></head><body><h1>Hello</h1></body></html>`)),
		"/favicon.ico": always(response(200, []string{"Content-Type: image/x-icon"}, ico)),
	})

	res := probeService(t, newProber(t, Options{}), srv.target("http"))
	obs := res.Observation

	if res.State != model.StateLive || obs.Error != "" {
		t.Fatalf("state = %s, error = %q", res.State, obs.Error)
	}
	if want := fmt.Sprintf("http://%s:%d", testHost, srv.port); obs.URL != want {
		t.Errorf("url = %q, want %q", obs.URL, want)
	}
	if want := []model.Hop{{Status: 200}}; !slices.Equal(obs.Hops, want) {
		t.Errorf("hops = %+v, want %+v", obs.Hops, want)
	}
	if want := []string{"Server", "Content-Type", "Set-Cookie", "X-Frame-Options", "Content-Length"}; !slices.Equal(obs.Headers.Names, want) {
		t.Errorf("header names = %q, want %q", obs.Headers.Names, want)
	}
	if want := map[string]string{"server": "nginx/1.24.0", "x-frame-options": "DENY"}; !maps.Equal(obs.Headers.Values, want) {
		t.Errorf("header values = %q, want %q", obs.Headers.Values, want)
	}
	if len(obs.Headers.Cookies) != 1 || obs.Headers.Cookies[0].Name != "session" {
		t.Errorf("cookies = %+v", obs.Headers.Cookies)
	}
	if strings.Contains(fmt.Sprintf("%+v", obs), "c2VjcmV0") {
		t.Error("a cookie value ended up in the observation")
	}
	if obs.Page == nil || obs.Page.Title != "Welcome" || obs.Page.Skeleton == "" || obs.Page.ContentType != "text/html" {
		t.Errorf("page = %+v", obs.Page)
	}
	if obs.Favicon == nil || *obs.Favicon != faviconHash([]byte(ico)) {
		t.Errorf("favicon = %v, want %d", obs.Favicon, faviconHash([]byte(ico)))
	}
	if obs.TLS != nil || res.Certs != nil || res.Leaf() != nil {
		t.Errorf("tls = %+v on a plain service", obs.TLS)
	}
	if len(obs.Volatile) != 0 {
		t.Errorf("volatile = %v, want nothing for identical samples", obs.Volatile)
	}

	// The whole footprint of a probe: the front page once per sample and
	// the icon.
	if want := []string{"/", "/", "/favicon.ico"}; !slices.Equal(srv.requests(), want) {
		t.Errorf("requests = %q, want %q", srv.requests(), want)
	}
}

func TestServiceFollowsRedirectsWithinTheOrigin(t *testing.T) {
	srv := serveSite(t, nil, map[string]route{
		"/":               always(redirect("/login?next=%2F")),
		"/login?next=%2F": always(htmlPage(`<title>Sign in</title><form action="session" method="post"><input type="password" name="pw"></form>`)),
	})

	obs := probeService(t, newProber(t, Options{}), srv.target("http")).Observation

	want := []model.Hop{
		{Status: 302, Location: fmt.Sprintf("http://%s:%d/login?next", testHost, srv.port), Relation: model.RelSameOrigin},
		{Status: 200},
	}
	if !slices.Equal(obs.Hops, want) {
		t.Errorf("hops = %+v\nwant   %+v", obs.Hops, want)
	}
	if obs.Page == nil || obs.Page.Title != "Sign in" {
		t.Fatalf("page = %+v, want the page the redirect leads to", obs.Page)
	}
	if got := obs.Page.Forms[0].Action; got != "/session" {
		t.Errorf("form action = %q, want it resolved against the final URL", got)
	}
	if want := []string{"/", "/login?next=%2F", "/", "/login?next=%2F", "/favicon.ico"}; !slices.Equal(srv.requests(), want) {
		t.Errorf("requests = %q, want %q", srv.requests(), want)
	}
}

func TestServiceRecordsRedirectsItDoesNotFollow(t *testing.T) {
	cases := []struct {
		name     string
		location string
		want     model.Hop
	}{
		{
			"upgrade to https",
			"https://" + testHost + "/",
			model.Hop{Status: 302, Location: "https://" + testHost + "/", Relation: model.RelSameHost},
		},
		{
			"another host of the target",
			"https://sso.example.test/login?return=42",
			model.Hop{Status: 302, Location: "https://sso.example.test/login?return", Relation: model.RelInScope},
		},
		{
			"outside the scope",
			"https://partner.example.org/landing/8842",
			model.Hop{Status: 302, Location: "https://partner.example.org/landing/*", Relation: model.RelExternal},
		},
	}
	for _, tc := range cases {
		srv := serveSite(t, nil, map[string]route{"/": always(redirect(tc.location))})

		res := probeService(t, newProber(t, Options{}), srv.target("http"))
		obs := res.Observation

		if res.State != model.StateLive {
			t.Errorf("%s: state = %s", tc.name, res.State)
		}
		if !slices.Equal(obs.Hops, []model.Hop{tc.want}) {
			t.Errorf("%s: hops = %+v, want %+v", tc.name, obs.Hops, tc.want)
		}
		if obs.Page != nil || obs.Favicon != nil {
			t.Errorf("%s: page = %+v, favicon = %v, want neither for a pure redirect", tc.name, obs.Page, obs.Favicon)
		}
		if obs.Headers == nil || !slices.Contains(obs.Headers.Names, "Location") {
			t.Errorf("%s: headers = %+v, want those of the redirect itself", tc.name, obs.Headers)
		}
		if want := []string{"/", "/"}; !slices.Equal(srv.requests(), want) {
			t.Errorf("%s: requests = %q, want %q", tc.name, srv.requests(), want)
		}
	}
}

func TestServiceStopsAtRedirectLoops(t *testing.T) {
	srv := serveSite(t, nil, map[string]route{
		"/":  always(redirect("/a")),
		"/a": always(redirect("/")),
	})

	obs := probeService(t, newProber(t, Options{}), srv.target("http")).Observation

	if len(obs.Hops) != 2 || obs.Hops[1].Status != 302 || obs.Hops[1].Relation != model.RelSameOrigin {
		t.Errorf("hops = %+v, want the loop cut after its second step", obs.Hops)
	}
	if want := []string{"/", "/a", "/", "/a"}; !slices.Equal(srv.requests(), want) {
		t.Errorf("requests = %q, want %q", srv.requests(), want)
	}
}

func TestServiceLimitsRedirects(t *testing.T) {
	var mu sync.Mutex
	step := 0
	srv := serveSite(t, nil, map[string]route{
		"*": func(int) string {
			mu.Lock()
			defer mu.Unlock()
			step++
			return redirect(fmt.Sprintf("/step/%c", 'a'+step))
		},
	})

	obs := probeService(t, newProber(t, Options{MaxRedirects: 3, Samples: 1}), srv.target("http")).Observation

	if len(obs.Hops) != 4 {
		t.Errorf("hops = %d, want the front page and 3 redirects followed", len(obs.Hops))
	}
	if got := len(srv.requests()); got != 4 {
		t.Errorf("requests = %d, want 4", got)
	}
}

func TestServiceMasksWhatDiffersBetweenSamples(t *testing.T) {
	srv := serveSite(t, nil, map[string]route{
		"/": func(n int) string {
			if n == 1 {
				return response(200, []string{
					"Server: backend-a",
					"X-Cache: MISS",
					"Content-Type: text/html",
					"Set-Cookie: sid=1; HttpOnly",
					"X-Frame-Options: DENY",
				}, `<title>Welcome</title><p>one</p>`)
			}
			return response(200, []string{
				"X-Frame-Options: DENY",
				"Server: backend-b",
				"Content-Type: text/html",
				"Set-Cookie: sid=2; HttpOnly",
				"X-Served-By: node2",
			}, `<title>Welcome</title><p>one</p><p>two</p><div></div>`)
		},
	})

	obs := probeService(t, newProber(t, Options{}), srv.target("http")).Observation

	wantVolatile := []string{"body", "dom", "header-order", "header:x-cache", "header:x-served-by", "value:server"}
	if !slices.Equal(obs.Volatile, wantVolatile) {
		t.Errorf("volatile = %q\nwant       %q", obs.Volatile, wantVolatile)
	}
	if want := []string{"Content-Length", "Content-Type", "Server", "Set-Cookie", "X-Frame-Options"}; !slices.Equal(obs.Headers.Names, want) {
		t.Errorf("header names = %q, want the shared ones as a set", obs.Headers.Names)
	}
	if want := map[string]string{"x-frame-options": "DENY"}; !maps.Equal(obs.Headers.Values, want) {
		t.Errorf("header values = %q, want %q", obs.Headers.Values, want)
	}
	if len(obs.Headers.Cookies) != 1 {
		t.Errorf("cookies = %+v, want the cookie kept: only its value changed", obs.Headers.Cookies)
	}
	if obs.Page.Title != "Welcome" || obs.Page.Skeleton != "" || obs.Page.BodySHA256 != "" || obs.Page.SimHash == nil {
		t.Errorf("page = %+v, want the stable title and no exact hashes", obs.Page)
	}
	if want := []model.Hop{{Status: 200}}; !slices.Equal(obs.Hops, want) {
		t.Errorf("hops = %+v", obs.Hops)
	}
}

func TestServiceThatCannotBeReached(t *testing.T) {
	p := newProber(t, Options{})

	closed := Target{Scheme: "http", Host: testHost, Port: closedPort(t), Addrs: loopback}
	res := probeService(t, p, closed)
	if res.State != model.StateUnreachable || res.Observation.Error != ReasonConnect {
		t.Errorf("closed port: state = %s, error = %q", res.State, res.Observation.Error)
	}
	if res.Observation.URL == "" || res.Observation.Headers != nil || res.Observation.Hops != nil {
		t.Errorf("closed port: observation = %+v, want nothing but the reason", res.Observation)
	}

	other := serveRaw(t, nil, respond("220 mail.example.test ESMTP\r\n"))
	res = probeService(t, p, Target{Scheme: "http", Host: testHost, Port: other.port, Addrs: loopback})
	if res.State != model.StateUnreachable || res.Observation.Error != ReasonProtocol {
		t.Errorf("other protocol: state = %s, error = %q", res.State, res.Observation.Error)
	}

	silent := serveRaw(t, nil, func(w io.Writer, _ *http.Request) { io.Copy(io.Discard, w.(io.Reader)) })
	res = probeService(t, newProber(t, Options{Timeout: 200 * time.Millisecond}), Target{Scheme: "http", Host: testHost, Port: silent.port, Addrs: loopback})
	if res.State != model.StateUnreachable || res.Observation.Error != ReasonTimeout {
		t.Errorf("silent server: state = %s, error = %q", res.State, res.Observation.Error)
	}
}

func TestServiceOnNonPublicAddressIsLeftAlone(t *testing.T) {
	srv := serveSite(t, nil, map[string]route{"/": always(htmlPage("<title>internal</title>"))})
	strict, err := New(Options{UserAgent: "driftrecon-test"})
	if err != nil {
		t.Fatal(err)
	}

	res := probeService(t, strict, srv.target("http"))

	if res.State != model.StateError || res.Observation.Error != ReasonNoAddress {
		t.Errorf("state = %s, error = %q", res.State, res.Observation.Error)
	}
	if got := srv.requests(); len(got) != 0 {
		t.Errorf("requests = %q, want no connection at all", got)
	}
}

func TestKnownServiceGetsASecondAttempt(t *testing.T) {
	routes := func() map[string]route {
		return map[string]route{
			"/": func(n int) string {
				if n == 1 {
					return ""
				}
				return htmlPage("<title>back</title>")
			},
		}
	}

	srv := serveSite(t, nil, routes())
	res := probeService(t, newProber(t, Options{}), srv.target("http"))
	if res.State != model.StateUnreachable {
		t.Errorf("new service: state = %s, want %s after a single attempt", res.State, model.StateUnreachable)
	}
	if got := srv.requests(); len(got) != 1 {
		t.Errorf("new service: requests = %q", got)
	}

	srv = serveSite(t, nil, routes())
	known := srv.target("http")
	known.Known = true
	res = probeService(t, newProber(t, Options{}), known)
	if res.State != model.StateLive || res.Observation.Page == nil || res.Observation.Page.Title != "back" {
		t.Errorf("known service: state = %s, page = %+v", res.State, res.Observation.Page)
	}
}

func TestServiceSurvivesAFailedSecondSample(t *testing.T) {
	srv := serveSite(t, nil, map[string]route{
		"/": func(n int) string {
			if n == 2 {
				return ""
			}
			return htmlPage("<title>flaky</title>")
		},
	})

	res := probeService(t, newProber(t, Options{}), srv.target("http"))

	if res.State != model.StateLive || res.Observation.Page.Title != "flaky" || len(res.Observation.Volatile) != 0 {
		t.Errorf("state = %s, observation = %+v", res.State, res.Observation)
	}
}

func TestServiceOverTLS(t *testing.T) {
	root := newAuthority(t, "Example Root", nil)
	cert := root.issue(t, leaf{names: []string{testHost}})
	srv := serveSite(t, serverConfig(cert), map[string]route{
		"/": always(response(200, []string{"Strict-Transport-Security: max-age=63072000", "Content-Type: text/html"}, "<title>secure</title>")),
	})

	res := probeService(t, newProber(t, Options{Roots: pool(root)}), srv.target("https"))
	obs := res.Observation

	if res.State != model.StateLive || obs.TLS == nil {
		t.Fatalf("state = %s, tls = %+v", res.State, obs.TLS)
	}
	if obs.TLS.Version != "TLS 1.3" || len(obs.TLS.Issues) != 0 || !slices.Equal(obs.TLS.Chain, []string{digest(cert.Leaf.Raw)}) {
		t.Errorf("tls = %+v", obs.TLS)
	}
	if leaf := res.Leaf(); leaf == nil || leaf.SubjectCN != testHost || leaf.IssuerCN != "Example Root" {
		t.Errorf("leaf = %+v", leaf)
	}
	if got := obs.Headers.Values["strict-transport-security"]; got != "max-age=63072000" {
		t.Errorf("hsts = %q", got)
	}
	if obs.Page == nil || obs.Page.Title != "secure" || len(obs.Volatile) != 0 {
		t.Errorf("page = %+v, volatile = %v", obs.Page, obs.Volatile)
	}
	if want := fmt.Sprintf("https://%s:%d", testHost, srv.port); obs.URL != want {
		t.Errorf("url = %q, want %q", obs.URL, want)
	}
}

func TestTLSEndpointWithoutHTTPIsStillAService(t *testing.T) {
	cert := (*authority)(nil).issue(t, leaf{names: []string{testHost}})
	srv := serveRaw(t, serverConfig(cert), respond("* OK IMAP4rev1 ready\r\n"))

	res := probeService(t, newProber(t, Options{}), Target{Scheme: "https", Host: testHost, Port: srv.port, Addrs: loopback})
	obs := res.Observation

	if res.State != model.StateLive || obs.Error != ReasonProtocol {
		t.Errorf("state = %s, error = %q, want a live service that does not speak HTTP", res.State, obs.Error)
	}
	if obs.TLS == nil || !slices.Equal(obs.TLS.Issues, []string{model.IssueSelfSigned}) || res.Leaf() == nil {
		t.Errorf("tls = %+v, leaf = %+v, want the certificate on record", obs.TLS, res.Leaf())
	}
	if obs.Headers != nil || obs.Hops != nil || obs.Page != nil {
		t.Errorf("observation = %+v, want no HTTP data", obs)
	}
}

func TestServiceWithInconsistentCertificates(t *testing.T) {
	first := (*authority)(nil).issue(t, leaf{names: []string{testHost}})
	second := (*authority)(nil).issue(t, leaf{names: []string{testHost}})

	var mu sync.Mutex
	connections := 0
	conf := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		connections++
		if connections%2 == 0 {
			return &second, nil
		}
		return &first, nil
	}}
	srv := serveSite(t, conf, map[string]route{"/": always(htmlPage("<title>pool</title>"))})

	res := probeService(t, newProber(t, Options{}), srv.target("https"))
	obs := res.Observation

	if !slices.Equal(obs.Volatile, []string{"tls"}) {
		t.Errorf("volatile = %v, want the certificate flagged", obs.Volatile)
	}
	if obs.TLS == nil || obs.TLS.Version == "" || obs.TLS.Chain != nil || obs.TLS.Issues != nil {
		t.Errorf("tls = %+v, want the negotiated parameters without a certificate", obs.TLS)
	}
	if res.Certs != nil || res.Leaf() != nil {
		t.Errorf("certificates = %+v, want none to stand for the service", res.Certs)
	}
	if obs.Page == nil || obs.Page.Title != "pool" {
		t.Errorf("page = %+v", obs.Page)
	}
}

func TestServiceFavicon(t *testing.T) {
	const png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

	cases := []struct {
		name   string
		page   string
		routes map[string]route
		want   *int32
		asked  string
	}{
		{
			name:   "conventional location",
			page:   "<title>x</title>",
			routes: map[string]route{"/favicon.ico": always(response(200, []string{"Content-Type: image/x-icon"}, ico))},
			want:   new(faviconHash([]byte(ico))),
			asked:  "/favicon.ico",
		},
		{
			name:   "declared by the page",
			page:   `<link rel="icon" href="/static/icon.png?v=3">`,
			routes: map[string]route{"/static/icon.png?v=3": always(response(200, []string{"Content-Type: image/png"}, png))},
			want:   new(faviconHash([]byte(png))),
			asked:  "/static/icon.png?v=3",
		},
		{
			name:  "hosted elsewhere",
			page:  `<link rel="icon" href="https://cdn.example.org/icon.png">`,
			asked: "",
		},
		{
			name:  "missing",
			page:  "<title>x</title>",
			asked: "/favicon.ico",
		},
		{
			name:   "application answering every path with its front page",
			page:   "<title>x</title>",
			routes: map[string]route{"/favicon.ico": always(htmlPage("<title>x</title>"))},
			asked:  "/favicon.ico",
		},
		{
			name:   "image without a content type",
			page:   "<title>x</title>",
			routes: map[string]route{"/favicon.ico": always(response(200, nil, png))},
			want:   new(faviconHash([]byte(png))),
			asked:  "/favicon.ico",
		},
		{
			name:   "empty",
			page:   "<title>x</title>",
			routes: map[string]route{"/favicon.ico": always(response(200, []string{"Content-Type: image/x-icon"}, ""))},
			asked:  "/favicon.ico",
		},
	}
	for _, tc := range cases {
		routes := map[string]route{"/": always(htmlPage(tc.page))}
		maps.Copy(routes, tc.routes)
		srv := serveSite(t, nil, routes)

		obs := probeService(t, newProber(t, Options{Samples: 1}), srv.target("http")).Observation

		switch {
		case tc.want == nil && obs.Favicon != nil:
			t.Errorf("%s: favicon = %d, want none", tc.name, *obs.Favicon)
		case tc.want != nil && (obs.Favicon == nil || *obs.Favicon != *tc.want):
			t.Errorf("%s: favicon = %v, want %d", tc.name, obs.Favicon, *tc.want)
		}

		want := []string{"/"}
		if tc.asked != "" {
			want = append(want, tc.asked)
		}
		if !slices.Equal(srv.requests(), want) {
			t.Errorf("%s: requests = %q, want %q", tc.name, srv.requests(), want)
		}
	}
}

func TestServiceIsInterruptible(t *testing.T) {
	srv := serveRaw(t, nil, func(w io.Writer, _ *http.Request) { io.Copy(io.Discard, w.(io.Reader)) })
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)

	target := Target{Scheme: "http", Host: testHost, Port: srv.port, Addrs: loopback, Known: true}
	_, err := newProber(t, Options{Timeout: 30 * time.Second}).Service(ctx, target)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
