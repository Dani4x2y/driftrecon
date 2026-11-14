package ctlog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dani4x2y/driftrecon/internal/collector"
)

var (
	_ collector.Source = (*CrtSh)(nil)
	_ collector.Source = (*CertSpotter)(nil)
)

func serve(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestCrtShEnumerate(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("q"); got != "%.example.com" {
			t.Errorf("q = %q, want %q", got, "%.example.com")
		}
		if got := r.URL.Query().Get("output"); got != "json" {
			t.Errorf("output = %q, want json", got)
		}
		if got := r.UserAgent(); got != "driftrecon/test" {
			t.Errorf("user agent = %q", got)
		}
		io.WriteString(w, `[
			{"common_name":"example.com","name_value":"example.com\nwww.example.com"},
			{"common_name":"*.dev.example.com","name_value":"*.dev.example.com\napi.example.com"},
			{"common_name":"Example Org","name_value":"www.example.com\nadmin@example.com\n"}
		]`)
	})

	src := NewCrtSh(Options{BaseURL: url, UserAgent: "driftrecon/test"})
	got, err := src.Enumerate(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"*.dev.example.com",
		"Example Org",
		"admin@example.com",
		"api.example.com",
		"example.com",
		"www.example.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
}

func TestCrtShEmptyResult(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `[]`)
	})
	got, err := NewCrtSh(Options{BaseURL: url}).Enumerate(t.Context(), "example.com")
	if err != nil || len(got) != 0 {
		t.Errorf("Enumerate = %q, %v; want no names and no error", got, err)
	}
}

func TestCrtShRejectsNonJSON(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `<html><body>too busy</body></html>`)
	})
	if _, err := NewCrtSh(Options{BaseURL: url}).Enumerate(t.Context(), "example.com"); err == nil {
		t.Fatal("an HTML answer was accepted")
	}
}

func TestCrtShKeepsNamesFromTruncatedResponse(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `[{"name_value":"a.example.com"},{"name_value":"b.exam`)
	})
	got, err := NewCrtSh(Options{BaseURL: url}).Enumerate(t.Context(), "example.com")
	if err == nil {
		t.Error("a truncated response must be reported")
	}
	if want := []string{"a.example.com"}; !slices.Equal(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
}

func TestRetriesTransientFailures(t *testing.T) {
	var calls atomic.Int32
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, `[{"name_value":"a.example.com"}]`)
	})

	src := NewCrtSh(Options{BaseURL: url, Backoff: time.Millisecond})
	got, err := src.Enumerate(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.example.com"}; !slices.Equal(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	src := NewCrtSh(Options{BaseURL: url, Backoff: time.Millisecond})
	if _, err := src.Enumerate(t.Context(), "example.com"); err == nil {
		t.Fatal("a persistent 503 must surface as an error")
	}
	if n := calls.Load(); n != maxAttempts {
		t.Errorf("requests = %d, want %d", n, maxAttempts)
	}
}

func TestDoesNotRetryPermanentFailures(t *testing.T) {
	var calls atomic.Int32
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})

	src := NewCrtSh(Options{BaseURL: url, Backoff: time.Millisecond})
	if _, err := src.Enumerate(t.Context(), "example.com"); err == nil {
		t.Fatal("a 404 must surface as an error")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestDoesNotWaitOutLongRetryAfter(t *testing.T) {
	var calls atomic.Int32
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	})

	src := NewCertSpotter(Options{BaseURL: url, Backoff: time.Millisecond})
	if _, err := src.Enumerate(t.Context(), "example.com"); err == nil {
		t.Fatal("a rate limit must surface as an error")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("requests = %d, want 1: an hour-long pause is not worth waiting for", n)
	}
}

func TestBackoffHonoursContext(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := NewCrtSh(Options{BaseURL: url, Backoff: 10 * time.Second}).Enumerate(ctx, "example.com")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("returned after %v, backoff ignored the context", elapsed)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := map[string]time.Duration{
		"":        0,
		"7":       7 * time.Second,
		"0":       0,
		"-5":      0,
		"soon":    0,
		"1.5":     0,
		"Mon, 02": 0,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}

	future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got < 80*time.Second || got > 90*time.Second {
		t.Errorf("parseRetryAfter(%q) = %v, want about 90s", future, got)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(past); got != 0 {
		t.Errorf("parseRetryAfter(%q) = %v, want 0", past, got)
	}
}

func TestCertSpotterPaginates(t *testing.T) {
	pages := map[string]string{
		"":   `[{"id":"10","dns_names":["a.example.com","example.com"]},{"id":"11","dns_names":["b.example.com"]}]`,
		"11": `[{"id":"12","dns_names":["c.example.com","a.example.com"]}]`,
		"12": `[]`,
	}
	var calls atomic.Int32
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		if q.Get("domain") != "example.com" || q.Get("include_subdomains") != "true" || q.Get("expand") != "dns_names" {
			t.Errorf("unexpected query %q", r.URL.RawQuery)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("authorization = %q", got)
		}
		body, ok := pages[q.Get("after")]
		if !ok {
			t.Errorf("unexpected cursor %q", q.Get("after"))
		}
		io.WriteString(w, body)
	})

	src := NewCertSpotter(Options{BaseURL: url, Token: "tok"})
	got, err := src.Enumerate(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com", "example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestCertSpotterWithoutToken(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Error("authorization header sent without a token")
		}
		io.WriteString(w, `[]`)
	})
	if _, err := NewCertSpotter(Options{BaseURL: url}).Enumerate(t.Context(), "example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestCertSpotterReturnsPartialResults(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after") == "" {
			io.WriteString(w, `[{"id":"10","dns_names":["a.example.com"]}]`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	src := NewCertSpotter(Options{BaseURL: url, Backoff: time.Millisecond})
	got, err := src.Enumerate(t.Context(), "example.com")
	if err == nil {
		t.Error("a failed page must be reported")
	}
	if want := []string{"a.example.com"}; !slices.Equal(got, want) {
		t.Errorf("names = %q, want the first page %q", got, want)
	}
}

func TestCertSpotterStopsAtPageLimit(t *testing.T) {
	var calls atomic.Int32
	url := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		io.WriteString(w, `[{"id":"1","dns_names":["a.example.com"]}]`)
	})

	got, err := NewCertSpotter(Options{BaseURL: url}).Enumerate(t.Context(), "example.com")
	if err == nil {
		t.Error("hitting the page limit must be reported")
	}
	if len(got) != 1 {
		t.Errorf("names = %q", got)
	}
	if n := calls.Load(); n != maxPages {
		t.Errorf("requests = %d, want %d", n, maxPages)
	}
}
