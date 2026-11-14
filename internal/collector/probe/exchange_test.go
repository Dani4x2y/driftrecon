package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func get(t *testing.T, p *Prober, o origin, target string) *exchange {
	t.Helper()
	x, err := p.get(t.Context(), o, loopback, 0, target)
	if err != nil {
		t.Fatalf("get %s: %v", target, err)
	}
	return x
}

// wantFailure asserts that err describes the service rather than the scan.
func wantFailure(t *testing.T, err error, reason string) {
	t.Helper()
	var f *failure
	if !errors.As(err, &f) {
		t.Fatalf("err = %v, want a failure", err)
	}
	if f.reason != reason {
		t.Errorf("reason = %q, want %q (%v)", f.reason, reason, err)
	}
}

func TestGetRecordsHeadersAsSent(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 200 OK\r\n"+
		"server: nginx\r\n"+
		"Date: Sun, 01 Mar 2026 12:00:00 GMT\r\n"+
		"X-Powered-By:PHP/8.2.10\r\n"+
		"Set-Cookie: a=1; Secure\r\n"+
		"Content-Security-Policy: default-src 'self';\r\n"+
		"\tscript-src 'none'\r\n"+
		"Set-Cookie: b=2\r\n"+
		"CONTENT-LENGTH: 2\r\n"+
		"\r\n"+
		"ok"))

	x := get(t, newProber(t, Options{}), srv.origin("http"), "/")

	want := []headerField{
		{"server", "nginx"},
		{"Date", "Sun, 01 Mar 2026 12:00:00 GMT"},
		{"X-Powered-By", "PHP/8.2.10"},
		{"Set-Cookie", "a=1; Secure"},
		{"Content-Security-Policy", "default-src 'self'; script-src 'none'"},
		{"Set-Cookie", "b=2"},
		{"CONTENT-LENGTH", "2"},
	}
	if !slices.Equal(x.fields, want) {
		t.Errorf("fields = %q\nwant     %q", x.fields, want)
	}
	if x.status != 200 || string(x.body) != "ok" || x.truncated || x.encoded {
		t.Errorf("status = %d, body = %q, truncated = %v, encoded = %v", x.status, x.body, x.truncated, x.encoded)
	}
	if got := x.header.Get("Server"); got != "nginx" {
		t.Errorf("parsed Server header = %q", got)
	}
}

func TestGetAcceptsBareLineFeeds(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.0 404 Not Found\nServer: tiny\nContent-Type: text/plain\n\ngone"))

	x := get(t, newProber(t, Options{}), srv.origin("http"), "/")

	want := []headerField{{"Server", "tiny"}, {"Content-Type", "text/plain"}}
	if x.status != 404 || !slices.Equal(x.fields, want) || string(x.body) != "gone" {
		t.Errorf("status = %d, fields = %q, body = %q", x.status, x.fields, x.body)
	}
}

func TestGetIdentifiesItself(t *testing.T) {
	var seen atomic.Pointer[http.Request]
	srv := serveRaw(t, nil, func(w io.Writer, r *http.Request) {
		seen.Store(r)
		io.WriteString(w, "HTTP/1.1 204 No Content\r\n\r\n")
	})
	p := newProber(t, Options{UserAgent: "driftrecon/1.2 (+https://example.org/about)"})

	get(t, p, srv.origin("http"), "/status?verbose=1")

	r := seen.Load()
	if r == nil {
		t.Fatal("no request reached the server")
	}
	if r.Method != http.MethodGet || r.RequestURI != "/status?verbose=1" || r.Proto != "HTTP/1.1" {
		t.Errorf("request line = %s %s %s", r.Method, r.RequestURI, r.Proto)
	}
	if want := fmt.Sprintf("%s:%d", testHost, srv.port); r.Host != want {
		t.Errorf("Host = %q, want %q", r.Host, want)
	}
	if got := r.Header.Get("User-Agent"); got != "driftrecon/1.2 (+https://example.org/about)" {
		t.Errorf("User-Agent = %q", got)
	}
	if got := r.Header.Get("Accept-Encoding"); got != "gzip" {
		t.Errorf("Accept-Encoding = %q", got)
	}
	if !r.Close {
		t.Error("the request does not ask for the connection to be closed")
	}
}

func TestHostHeaderOmitsDefaultPort(t *testing.T) {
	cases := map[origin]string{
		{scheme: "http", host: testHost, port: 80}:    testHost,
		{scheme: "https", host: testHost, port: 443}:  testHost,
		{scheme: "http", host: testHost, port: 443}:   testHost + ":443",
		{scheme: "https", host: testHost, port: 8443}: testHost + ":8443",
	}
	for o, want := range cases {
		if got := o.authority(); got != want {
			t.Errorf("%+v: authority = %q, want %q", o, got, want)
		}
	}
}

func TestGetSkipsInformationalResponses(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 103 Early Hints\r\n"+
		"Link: </app.css>; rel=preload\r\n"+
		"\r\n"+
		"HTTP/1.1 200 OK\r\n"+
		"Server: edge\r\n"+
		"Content-Length: 4\r\n"+
		"\r\n"+
		"body"))

	x := get(t, newProber(t, Options{}), srv.origin("http"), "/")

	want := []headerField{{"Server", "edge"}, {"Content-Length", "4"}}
	if x.status != 200 || !slices.Equal(x.fields, want) || string(x.body) != "body" {
		t.Errorf("status = %d, fields = %q, body = %q", x.status, x.fields, x.body)
	}
}

func TestGetDecodesGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	io.WriteString(zw, "<html><title>compressed</title></html>")
	zw.Close()

	srv := serveRaw(t, nil, respond(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", buf.Len(), buf.String())))

	x := get(t, newProber(t, Options{}), srv.origin("http"), "/")
	if string(x.body) != "<html><title>compressed</title></html>" || x.encoded {
		t.Errorf("body = %q, encoded = %v", x.body, x.encoded)
	}
}

func TestGetLeavesUnknownEncodingAlone(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\n\x0b\x01\x80\x03"))

	x := get(t, newProber(t, Options{}), srv.origin("http"), "/")
	if !x.encoded || len(x.body) != 4 {
		t.Errorf("encoded = %v, body = %q", x.encoded, x.body)
	}
}

func TestGetRejectsBrokenGzip(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 9\r\n\r\nnot gzip!"))

	_, err := newProber(t, Options{}).get(t.Context(), srv.origin("http"), loopback, 0, "/")
	wantFailure(t, err, ReasonProtocol)
}

func TestGetCapsBody(t *testing.T) {
	const limit = 1000
	plain := strings.Repeat("0123456789", 500)

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	io.WriteString(zw, plain)
	zw.Close()

	cases := map[string]string{
		"declared length": fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(plain), plain),
		"until close":     "HTTP/1.1 200 OK\r\n\r\n" + plain,
		"chunked":         fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(plain), plain),
		// The compressed form fits the limit, the content does not.
		"compressed": fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", buf.Len(), buf.String()),
	}
	for name, response := range cases {
		srv := serveRaw(t, nil, respond(response))
		x := get(t, newProber(t, Options{MaxBody: limit}), srv.origin("http"), "/")
		if !x.truncated || string(x.body) != plain[:limit] {
			t.Errorf("%s: truncated = %v, body is %d bytes, want the first %d", name, x.truncated, len(x.body), limit)
		}
	}

	srv := serveRaw(t, nil, respond(cases["declared length"]))
	x := get(t, newProber(t, Options{MaxBody: int64(len(plain))}), srv.origin("http"), "/")
	if x.truncated || string(x.body) != plain {
		t.Errorf("a body of exactly the limit: truncated = %v, %d bytes", x.truncated, len(x.body))
	}
}

func TestGetDoesNotReadRedirectBodies(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 5\r\n\r\nmoved"))

	x := get(t, newProber(t, Options{}), srv.origin("http"), "/")
	if !x.redirects() || len(x.body) != 0 {
		t.Errorf("redirects = %v, body = %q", x.redirects(), x.body)
	}

	// Without a target there is nowhere to go, so the response is final.
	srv = serveRaw(t, nil, respond("HTTP/1.1 302 Found\r\nContent-Length: 5\r\n\r\nmoved"))
	x = get(t, newProber(t, Options{}), srv.origin("http"), "/")
	if x.redirects() || string(x.body) != "moved" {
		t.Errorf("redirects = %v, body = %q", x.redirects(), x.body)
	}
}

func TestGetRejectsOversizedHeaders(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 200 OK\r\nX-Padding: "+strings.Repeat("a", maxHeadBytes)+"\r\nContent-Length: 0\r\n\r\n"))

	_, err := newProber(t, Options{}).get(t.Context(), srv.origin("http"), loopback, 0, "/")
	wantFailure(t, err, ReasonProtocol)
}

func TestGetRejectsOtherProtocols(t *testing.T) {
	srv := serveRaw(t, nil, respond("SSH-2.0-OpenSSH_9.6\r\n"))

	_, err := newProber(t, Options{}).get(t.Context(), srv.origin("http"), loopback, 0, "/")
	wantFailure(t, err, ReasonProtocol)
}

func TestGetRejectsBodyCutShort(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial"))

	_, err := newProber(t, Options{}).get(t.Context(), srv.origin("http"), loopback, 0, "/")
	wantFailure(t, err, ReasonProtocol)
}

func TestGetTimesOut(t *testing.T) {
	srv := serveRaw(t, nil, func(w io.Writer, _ *http.Request) {
		io.Copy(io.Discard, w.(io.Reader))
	})
	p := newProber(t, Options{Timeout: 200 * time.Millisecond})

	start := time.Now()
	_, err := p.get(t.Context(), srv.origin("http"), loopback, 0, "/")
	wantFailure(t, err, ReasonTimeout)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("gave up after %v, want about the timeout", elapsed)
	}
}

func TestGetStopsWhenScanIsCancelled(t *testing.T) {
	srv := serveRaw(t, nil, func(w io.Writer, _ *http.Request) {
		io.Copy(io.Discard, w.(io.Reader))
	})
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := newProber(t, Options{Timeout: 30 * time.Second}).get(ctx, srv.origin("http"), loopback, 0, "/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("returned after %v, want promptly", elapsed)
	}
}

func TestConnectFailure(t *testing.T) {
	o := origin{scheme: "http", host: testHost, port: closedPort(t)}

	_, err := newProber(t, Options{}).get(t.Context(), o, loopback, 0, "/")
	wantFailure(t, err, ReasonConnect)
}

func TestConnectTriesTheNextAddress(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 204 No Content\r\n\r\n"))
	// Nothing listens on the first address: the server is bound to
	// 127.0.0.1 only.
	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}

	p := newProber(t, Options{})
	x, err := p.get(t.Context(), srv.origin("http"), addrs, 0, "/")
	if err != nil || x.status != 204 {
		t.Fatalf("status = %v, err = %v", x, err)
	}

	// The rotation decides where to start, not which addresses are tried.
	if x, err = p.get(t.Context(), srv.origin("http"), addrs, 1, "/"); err != nil || x.status != 204 {
		t.Fatalf("status = %v, err = %v", x, err)
	}
}

type countingLimiter struct {
	calls atomic.Int32
}

func (l *countingLimiter) Wait(context.Context) error {
	l.calls.Add(1)
	return nil
}

func TestEveryConnectionIsRateLimited(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 204 No Content\r\n\r\n"))
	global := &countingLimiter{}
	// 20 connections per second leave 50 ms between two of them.
	p := newProber(t, Options{Limiter: global, HostRate: 20})

	start := time.Now()
	for range 5 {
		get(t, p, srv.origin("http"), "/")
	}
	if elapsed := time.Since(start); elapsed < 190*time.Millisecond {
		t.Errorf("5 requests to one host took %v, want at least 200ms", elapsed)
	}
	if n := global.calls.Load(); n != 5 {
		t.Errorf("global limiter consulted %d times, want 5", n)
	}

	if p.hostLimiter("api.example.test") == p.hostLimiter(testHost) {
		t.Error("two hosts share one budget")
	}
}

func TestBackoff(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	response := func(status int, retryAfter string) *exchange {
		x := &exchange{status: status, header: http.Header{}}
		if retryAfter != "" {
			x.header.Set("Retry-After", retryAfter)
		}
		return x
	}

	cases := []struct {
		name string
		x    *exchange
		want time.Duration
		ok   bool
	}{
		{"ok", response(200, ""), 0, false},
		{"ok with header", response(200, "5"), 0, false},
		{"unavailable without hint", response(503, ""), 0, false},
		{"unavailable with seconds", response(503, "7"), 7 * time.Second, true},
		{"too many requests", response(429, ""), time.Second, true},
		{"too many requests with seconds", response(429, " 3 "), 3 * time.Second, true},
		{"zero", response(429, "0"), 0, true},
		{"date", response(429, "Sun, 01 Mar 2026 12:00:20 GMT"), 20 * time.Second, true},
		{"date in the past", response(429, "Sun, 01 Mar 2026 11:00:00 GMT"), 0, true},
		{"garbage", response(429, "soon"), time.Second, true},
	}
	for _, tc := range cases {
		got, ok := backoff(tc.x, now)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: backoff = %v, %v, want %v, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFetchBacksOffAndSlowsDown(t *testing.T) {
	var n atomic.Int32
	srv := serveRaw(t, nil, func(w io.Writer, _ *http.Request) {
		if n.Add(1) == 1 {
			io.WriteString(w, "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n")
			return
		}
		io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	p := newProber(t, Options{HostRate: 400})

	x, err := p.fetch(t.Context(), srv.origin("http"), loopback, 0, "/")
	if err != nil || x.status != 200 {
		t.Fatalf("exchange = %+v, err = %v", x, err)
	}
	if got := srv.requests.Load(); got != 2 {
		t.Errorf("requests = %d, want the original and one repeat", got)
	}
	if got := p.hostLimiter(testHost).Limit(); got != 200 {
		t.Errorf("host rate = %v, want it halved to 200", got)
	}
}

func TestFetchDoesNotWaitOutLongPauses(t *testing.T) {
	srv := serveRaw(t, nil, respond("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 3600\r\nContent-Length: 0\r\n\r\n"))
	p := newProber(t, Options{})

	start := time.Now()
	x, err := p.fetch(t.Context(), srv.origin("http"), loopback, 0, "/")
	if err != nil || x.status != 503 {
		t.Fatalf("exchange = %+v, err = %v", x, err)
	}
	if got := srv.requests.Load(); got != 1 {
		t.Errorf("requests = %d, want no repeat", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("fetch took %v", elapsed)
	}
}

func TestHostRateHasAFloor(t *testing.T) {
	p := newProber(t, Options{HostRate: 0.3})
	for range 5 {
		p.slowDown(testHost)
	}
	if got := p.hostLimiter(testHost).Limit(); got != minHostRate {
		t.Errorf("host rate = %v, want the floor of %v", got, minHostRate)
	}
}

func TestNewValidatesUserAgent(t *testing.T) {
	for _, ua := range []string{"", "driftrecon\r\nX-Injected: 1", "driftrecon\n"} {
		if _, err := New(Options{UserAgent: ua}); err == nil {
			t.Errorf("user agent %q was accepted", ua)
		}
	}
}
