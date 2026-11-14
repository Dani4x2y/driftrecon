package resolve

import (
	"context"
	"crypto/rand"
	"net/netip"
	"strings"
	"sync"
)

// wildcardProbes is how many random names must all resolve before a zone is
// considered to have a wildcard record.
const wildcardProbes = 3

// Wildcard describes what a zone answers for names that do not exist.
type Wildcard struct {
	addrs  map[netip.Addr]struct{}
	cnames map[string]struct{}
}

// Matches reports whether res is indistinguishable from the wildcard answer.
// A nil Wildcard matches nothing.
func (w *Wildcard) Matches(res Result) bool {
	if w == nil {
		return false
	}
	if n := len(res.CNAME); n > 0 {
		_, ok := w.cnames[res.CNAME[n-1]]
		return ok
	}
	if !res.Resolved() {
		return false
	}
	for _, addrs := range [][]netip.Addr{res.A, res.AAAA} {
		for _, addr := range addrs {
			if _, ok := w.addrs[addr]; !ok {
				return false
			}
		}
	}
	return true
}

type wildcardProbe struct {
	once     sync.Once
	wildcard *Wildcard
	err      error
}

// Wildcard reports the wildcard answer of zone, or nil if it has none. The
// zone is probed once per Resolver and the outcome, including a failure, is
// reused for every later call.
func (r *Resolver) Wildcard(ctx context.Context, zone string) (*Wildcard, error) {
	r.mu.Lock()
	p, ok := r.wildcards[zone]
	if !ok {
		p = new(wildcardProbe)
		r.wildcards[zone] = p
	}
	r.mu.Unlock()

	p.once.Do(func() {
		p.wildcard, p.err = r.probeWildcard(ctx, zone)
	})
	return p.wildcard, p.err
}

func (r *Resolver) probeWildcard(ctx context.Context, zone string) (*Wildcard, error) {
	w := &Wildcard{
		addrs:  make(map[netip.Addr]struct{}),
		cnames: make(map[string]struct{}),
	}
	for range wildcardProbes {
		res, err := r.Lookup(ctx, strings.ToLower(rand.Text())+"."+zone)
		if err != nil {
			return nil, err
		}
		// A wildcard answers every name, so a single miss rules it out.
		if !res.Resolved() && len(res.CNAME) == 0 {
			return nil, nil
		}
		if n := len(res.CNAME); n > 0 {
			w.cnames[res.CNAME[n-1]] = struct{}{}
		}
		for _, addrs := range [][]netip.Addr{res.A, res.AAAA} {
			for _, addr := range addrs {
				w.addrs[addr] = struct{}{}
			}
		}
	}
	return w, nil
}
