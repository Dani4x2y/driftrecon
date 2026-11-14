// Package ctlog discovers hostnames through Certificate Transparency search
// services.
package ctlog

import (
	"context"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxAttempts    = 4
	defaultBackoff = 2 * time.Second

	// maxWait caps a single pause between attempts. A service that asks for
	// a longer pause is treated as unavailable for this scan.
	maxWait = 30 * time.Second

	// maxResponseBytes bounds how much of a response body is read. Results
	// for large organisations run to tens of megabytes.
	maxResponseBytes = 256 << 20
)

// Options configures a source.
type Options struct {
	// HTTPClient defaults to a client with a 90 second timeout.
	HTTPClient *http.Client
	// UserAgent is sent with every request.
	UserAgent string
	// BaseURL overrides the service endpoint.
	BaseURL string
	// Token authenticates against services that accept one.
	Token string
	// Backoff is the pause before the first retry and doubles with every
	// further attempt. It defaults to 2 seconds.
	Backoff time.Duration
}

type client struct {
	http      *http.Client
	userAgent string
	backoff   time.Duration
}

func newClient(o Options) *client {
	c := &client{http: o.HTTPClient, userAgent: o.UserAgent, backoff: o.Backoff}
	if c.http == nil {
		c.http = &http.Client{Timeout: 90 * time.Second}
	}
	if c.backoff <= 0 {
		c.backoff = defaultBackoff
	}
	return c
}

// get performs a GET and retries transient failures. The response it returns
// always has status 200, and the caller must close its body.
func (c *client) get(ctx context.Context, url string, header http.Header) (*http.Response, error) {
	var (
		lastErr error
		wait    time.Duration
	)
	for attempt := range maxAttempts {
		if attempt > 0 {
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		for name, values := range header {
			req.Header[name] = values
		}
		req.Header.Set("Accept", "application/json")
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			wait = c.pause(attempt, 0)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		discard(resp.Body)
		lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		if !transient(resp.StatusCode) {
			return nil, lastErr
		}
		if retryAfter > maxWait {
			return nil, fmt.Errorf("%w, retry allowed in %s", lastErr, retryAfter.Round(time.Second))
		}
		wait = c.pause(attempt, retryAfter)
	}
	return nil, lastErr
}

// pause returns how long to wait after the given attempt: exponential
// backoff with jitter, or the server's Retry-After when that is longer.
func (c *client) pause(attempt int, retryAfter time.Duration) time.Duration {
	d := min(c.backoff<<attempt, maxWait)
	d += rand.N(d/4 + 1)
	return max(d, retryAfter)
}

func transient(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// parseRetryAfter understands both forms of the header: a number of seconds
// and an HTTP date. Anything else counts as no hint.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return max(time.Duration(secs)*time.Second, 0)
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0)
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// discard reads a little of the body so the connection can be reused, then
// closes it.
func discard(body io.ReadCloser) {
	io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	body.Close()
}

type nameSet map[string]struct{}

func (s nameSet) add(name string) {
	if name = strings.TrimSpace(name); name != "" {
		s[name] = struct{}{}
	}
}

func (s nameSet) sorted() []string {
	return slices.Sorted(maps.Keys(s))
}
