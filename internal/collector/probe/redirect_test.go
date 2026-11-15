package probe

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

func inExampleScope(host string) bool {
	return host == "example.test" || strings.HasSuffix(host, ".example.test")
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRelation(t *testing.T) {
	o := origin{scheme: "https", host: "www.example.test", port: 443}

	cases := map[string]model.Relation{
		"https://www.example.test/login":     model.RelSameOrigin,
		"https://www.example.test:443/":      model.RelSameOrigin,
		"https://WWW.Example.TEST./":         model.RelSameOrigin,
		"http://www.example.test/":           model.RelSameHost,
		"https://www.example.test:8443/":     model.RelSameHost,
		"https://sso.example.test/auth":      model.RelInScope,
		"https://example.test/":              model.RelInScope,
		"https://login.example.org/":         model.RelExternal,
		"https://www.example.test.evil.org/": model.RelExternal,
		"https://203.0.113.5/":               model.RelExternal,
		"https://localhost/":                 model.RelExternal,
		"ftp://www.example.test/":            model.RelExternal,
		"mailto:admin@example.test":          model.RelExternal,
	}
	for raw, want := range cases {
		if got := o.relation(mustParse(t, raw), inExampleScope); got != want {
			t.Errorf("%s: relation = %s, want %s", raw, got, want)
		}
	}

	if got := o.relation(mustParse(t, "https://sso.example.test/"), nil); got != model.RelExternal {
		t.Errorf("relation without a scope = %s, want %s", got, model.RelExternal)
	}

	plain := origin{scheme: "http", host: "www.example.test", port: 8080}
	if got := plain.relation(mustParse(t, "http://www.example.test:8080/x"), nil); got != model.RelSameOrigin {
		t.Errorf("relation on a custom port = %s", got)
	}
	if got := plain.relation(mustParse(t, "http://www.example.test/x"), nil); got != model.RelSameHost {
		t.Errorf("relation to the default port = %s", got)
	}
}

func TestLocationPattern(t *testing.T) {
	cases := map[string]string{
		"https://www.example.test/login?next=%2Fhome&state=abc123":                        "https://www.example.test/login?next&state",
		"https://WWW.Example.test:443/":                                                   "https://www.example.test/",
		"http://www.example.test:8080":                                                    "http://www.example.test:8080/",
		"http://www.example.test:80/a":                                                    "http://www.example.test/a",
		"https://www.example.test/a?b=1&a=2&b=3&c&=x":                                     "https://www.example.test/a?a&b&c",
		"https://www.example.test/orders/1042/items/550e8400-e29b-41d4-a716-446655440000": "https://www.example.test/orders/*/items/*",
		"https://www.example.test/app;jsessionid=A1B2C3D4E5F6A7B8/home":                   "https://www.example.test/app/home",
		"https://www.example.test/(S(lit3py55t21z5v55vlm25s55))/default.aspx":             "https://www.example.test/(S(*))/default.aspx",
		"https://www.example.test/caf%C3%A9/":                                             "https://www.example.test/caf%C3%A9/",
		"https://[2001:db8::1]:8443/x":                                                    "https://[2001:db8::1]:8443/x",
		"mailto:admin@example.test":                                                       "mailto:",
		"app://open/session/42":                                                           "app:",
	}
	for raw, want := range cases {
		if got := locationPattern(mustParse(t, raw)); got != want {
			t.Errorf("%s:\n got %s\nwant %s", raw, got, want)
		}
	}
}

func TestRedirectTarget(t *testing.T) {
	from := mustParse(t, "https://www.example.test/app/start?x=1")
	response := func(status int, location string) *exchange {
		x := &exchange{status: status, header: http.Header{}}
		if location != "" {
			x.header.Set("Location", location)
		}
		return x
	}

	cases := []struct {
		name string
		x    *exchange
		want string
	}{
		{"absolute", response(301, "https://sso.example.test/login"), "https://sso.example.test/login"},
		{"absolute path", response(302, "/login?next=/"), "https://www.example.test/login?next=/"},
		{"relative path", response(303, "step2"), "https://www.example.test/app/step2"},
		{"parent path", response(307, "../other"), "https://www.example.test/other"},
		{"scheme relative", response(308, "//cdn.example.org/x"), "https://cdn.example.org/x"},
		{"fragment", response(302, "/app#section"), "https://www.example.test/app"},
		{"not a redirect", response(200, "/ignored"), ""},
		{"not followed by browsers", response(300, "/choices"), ""},
		{"no target", response(302, ""), ""},
		{"malformed target", response(302, "http://[::1"), ""},
	}
	for _, tc := range cases {
		got := ""
		if u := redirectTarget(tc.x, from); u != nil {
			got = u.String()
		}
		if got != tc.want {
			t.Errorf("%s: target = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRequestTarget(t *testing.T) {
	cases := map[string]string{
		"https://www.example.test":             "/",
		"https://www.example.test/a/b?c=d":     "/a/b?c=d",
		"https://www.example.test/a b?q=x y":   "/a%20b?q=x%20y",
		"https://www.example.test/%2e%2e/etc":  "/%2e%2e/etc",
		"https://www.example.test/caf%C3%A9?x": "/caf%C3%A9?x",
	}
	for raw, want := range cases {
		if got := requestTarget(mustParse(t, raw)); got != want {
			t.Errorf("%s: target = %q, want %q", raw, got, want)
		}
	}
}
