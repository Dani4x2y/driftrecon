package probe

import (
	"bufio"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// parseExchange builds an exchange from the text of a response, the way a
// request would have.
func parseExchange(t *testing.T, raw string) *exchange {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	fields, err := finalHead([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return &exchange{status: resp.StatusCode, fields: fields, header: resp.Header, body: body}
}

func TestSummarizeHeaders(t *testing.T) {
	x := parseExchange(t, "HTTP/1.1 200 OK\r\n"+
		"Server: nginx/1.24.0\r\n"+
		"Date: Sun, 01 Mar 2026 12:00:00 GMT\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Set-Cookie: session=c2VjcmV0; Path=/; HttpOnly; Secure; SameSite=Lax\r\n"+
		"Age: 17\r\n"+
		"Set-Cookie: lang=en; Path=/\r\n"+
		"X-Request-Id: 7f3a9c2b1d4e\r\n"+
		"strict-transport-security: max-age=31536000;   includeSubDomains\r\n"+
		"Content-Security-Policy: default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'\r\n"+
		"Via: 1.1 2e2c0e9ac1f3.cloudfront.net (CloudFront)\r\n"+
		"WWW-Authenticate: Digest realm=\"admin\", nonce=\"dcd98b7102dd2f0e\", opaque=\"5ccc069c403ebaf9\", qop=\"auth\"\r\n"+
		"Content-Length: 0\r\n"+
		"\r\n")

	h := summarizeHeaders(x)

	wantNames := []string{
		"Server", "Date", "Content-Type", "Set-Cookie", "X-Request-Id", "strict-transport-security",
		"Content-Security-Policy", "Via", "WWW-Authenticate", "Content-Length",
	}
	if !slices.Equal(h.Names, wantNames) {
		t.Errorf("names = %q\nwant    %q", h.Names, wantNames)
	}

	wantValues := map[string]string{
		"server":                    "nginx/1.24.0",
		"strict-transport-security": "max-age=31536000; includeSubDomains",
		"content-security-policy":   "default-src 'self'; script-src 'nonce-*' 'strict-dynamic'",
		"via":                       "1.1 *.cloudfront.net (CloudFront)",
		"www-authenticate":          `Digest realm="admin", nonce="*", opaque="*", qop="auth"`,
	}
	if !maps.Equal(h.Values, wantValues) {
		t.Errorf("values = %q\nwant     %q", h.Values, wantValues)
	}

	wantCookies := []model.Cookie{
		{Name: "session", Flags: []string{"httponly", "samesite=lax", "secure"}},
		{Name: "lang"},
	}
	if !slices.EqualFunc(h.Cookies, wantCookies, func(a, b model.Cookie) bool {
		return a.Name == b.Name && slices.Equal(a.Flags, b.Flags)
	}) {
		t.Errorf("cookies = %+v\nwant      %+v", h.Cookies, wantCookies)
	}
}

func TestSummarizeHeadersJoinsRepeatedPolicies(t *testing.T) {
	x := parseExchange(t, "HTTP/1.1 200 OK\r\n"+
		"Content-Security-Policy: default-src 'self'\r\n"+
		"Content-Security-Policy: frame-ancestors 'none'\r\n"+
		"\r\n")

	h := summarizeHeaders(x)
	if got, want := h.Values["content-security-policy"], "default-src 'self', frame-ancestors 'none'"; got != want {
		t.Errorf("policy = %q, want %q", got, want)
	}
	if want := []string{"Content-Security-Policy"}; !slices.Equal(h.Names, want) {
		t.Errorf("names = %q, want %q", h.Names, want)
	}
}

func TestSummarizeHeadersOfBareResponse(t *testing.T) {
	h := summarizeHeaders(parseExchange(t, "HTTP/1.0 200 OK\r\n\r\n"))
	if h == nil || len(h.Names) != 0 || h.Values != nil || h.Cookies != nil {
		t.Errorf("headers = %+v, want an empty summary", h)
	}
}

func TestCookies(t *testing.T) {
	got := cookies([]string{
		"__Host-id=1; Secure; Path=/; SameSite=Strict; Partitioned",
		"sess_8f3a9c2b1d4e=x",
		"__Host-id=2",
		"=nameless",
		"no-equals-sign",
		" spaced = v ;  SECURE ; httponly",
	})
	want := []model.Cookie{
		{Name: "__Host-id", Flags: []string{"partitioned", "samesite=strict", "secure"}},
		{Name: "sess_*"},
		{Name: "spaced", Flags: []string{"httponly", "secure"}},
	}
	if !slices.EqualFunc(got, want, func(a, b model.Cookie) bool {
		return a.Name == b.Name && slices.Equal(a.Flags, b.Flags)
	}) {
		t.Errorf("cookies = %+v\nwant      %+v", got, want)
	}
}
