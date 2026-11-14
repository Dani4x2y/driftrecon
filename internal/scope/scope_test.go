package scope

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	valid := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"},
		{"  api.example.com\t", "api.example.com"},
		{"*.dev.example.com", "dev.example.com"},
		{"bücher.example.com", "xn--bcher-kva.example.com"},
		{"xn--bcher-kva.example.com", "xn--bcher-kva.example.com"},
		{"_dmarc.example.com", "_dmarc.example.com"},
		{"ab--cd.example.com", "ab--cd.example.com"},
		{"a.b.c.d.example.co.uk", "a.b.c.d.example.co.uk"},
	}
	for _, tc := range valid {
		got, err := NormalizeHost(tc.in)
		if err != nil {
			t.Errorf("NormalizeHost(%q) returned error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalid := []string{
		"",
		"   ",
		"localhost",
		"192.0.2.10",
		"2001:db8::1",
		"admin@example.com",
		"foo bar.example.com",
		"example..com",
		"https://example.com",
		"example.com/path",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 127) + "example.com",
	}
	for _, in := range invalid {
		if got, err := NormalizeHost(in); !errors.Is(err, ErrInvalidHost) {
			t.Errorf("NormalizeHost(%q) = %q, %v; want ErrInvalidHost", in, got, err)
		}
	}
}

func TestNewCanonicalisesRules(t *testing.T) {
	s, err := New(Rules{
		Roots:   []string{"Example.org.", "example.com", "EXAMPLE.com"},
		Include: []string{" *.Prod.example.com ", ""},
		Exclude: []string{"legacy.example.com", "legacy.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := s.Rules()
	if want := []string{"example.com", "example.org"}; !slices.Equal(got.Roots, want) {
		t.Errorf("roots = %v, want %v", got.Roots, want)
	}
	if want := []string{"*.prod.example.com"}; !slices.Equal(got.Include, want) {
		t.Errorf("include = %v, want %v", got.Include, want)
	}
	if want := []string{"legacy.example.com"}; !slices.Equal(got.Exclude, want) {
		t.Errorf("exclude = %v, want %v", got.Exclude, want)
	}
}

func TestNewRejectsUnsafeRules(t *testing.T) {
	cases := map[string]Rules{
		"no roots":           {},
		"tld":                {Roots: []string{"com"}},
		"public suffix":      {Roots: []string{"co.uk"}},
		"private suffix":     {Roots: []string{"github.io"}},
		"ip address":         {Roots: []string{"192.0.2.1"}},
		"malformed include":  {Roots: []string{"example.com"}, Include: []string{"[a-"}},
		"malformed exclude":  {Roots: []string{"example.com"}, Exclude: []string{"dev[.example.com"}},
		"one invalid of two": {Roots: []string{"example.com", "not a host"}},
	}
	for name, rules := range cases {
		if _, err := New(rules); err == nil {
			t.Errorf("%s: New(%+v) succeeded, want error", name, rules)
		}
	}
}

func TestContains(t *testing.T) {
	s, err := New(Rules{
		Roots:   []string{"example.com", "example.org"},
		Exclude: []string{"*.corp.example.com", "vpn.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{
		"example.com":              true,
		"www.example.com":          true,
		"a.b.c.example.com":        true,
		"example.org":              true,
		"corp.example.com":         true,
		"vpn.example.com":          false,
		"db.corp.example.com":      false,
		"a.db.corp.example.com":    false,
		"notexample.com":           false,
		"example.com.attacker.net": false,
		"example.net":              false,
		"com":                      false,
	}
	for host, want := range cases {
		if got := s.Contains(host); got != want {
			t.Errorf("Contains(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestContainsWithInclude(t *testing.T) {
	s, err := New(Rules{
		Roots:   []string{"example.com"},
		Include: []string{"*.prod.example.com", "www.example.com"},
		Exclude: []string{"db.prod.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]bool{
		"www.example.com":      true,
		"api.prod.example.com": true,
		"db.prod.example.com":  false,
		"example.com":          false,
		"dev.example.com":      false,
	}
	for host, want := range cases {
		if got := s.Contains(host); got != want {
			t.Errorf("Contains(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestIsRoot(t *testing.T) {
	s, err := New(Rules{Roots: []string{"example.org", "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsRoot("example.com") || !s.IsRoot("example.org") {
		t.Error("IsRoot is false for a configured root")
	}
	if s.IsRoot("www.example.com") {
		t.Error("IsRoot is true for a subdomain")
	}
}
