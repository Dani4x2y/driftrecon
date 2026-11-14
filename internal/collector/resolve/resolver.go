// Package resolve performs DNS lookups against a fixed set of recursive
// resolvers.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Limiter throttles outgoing queries. *rate.Limiter satisfies it.
type Limiter interface {
	Wait(ctx context.Context) error
}

// Options configures a Resolver.
type Options struct {
	// Servers are recursive resolvers in ip:port form.
	Servers []string
	// Timeout bounds a single query. It defaults to 5 seconds.
	Timeout time.Duration
	// Attempts is how many servers are tried per query before giving up.
	// It defaults to 3.
	Attempts int
	// Limiter, when set, is consulted before every query sent.
	Limiter Limiter
}

// Resolver resolves names through its configured servers, rotating between
// them. It is safe for concurrent use.
type Resolver struct {
	servers  []string
	udp, tcp *dns.Client
	attempts int
	limiter  Limiter
	next     atomic.Uint32

	mu        sync.Mutex
	wildcards map[string]*wildcardProbe
}

// New returns a Resolver.
func New(o Options) (*Resolver, error) {
	if len(o.Servers) == 0 {
		return nil, errors.New("resolve: no servers configured")
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Attempts <= 0 {
		o.Attempts = 3
	}
	return &Resolver{
		servers:   slices.Clone(o.Servers),
		udp:       &dns.Client{Net: "udp", Timeout: o.Timeout},
		tcp:       &dns.Client{Net: "tcp", Timeout: o.Timeout},
		attempts:  o.Attempts,
		limiter:   o.Limiter,
		wildcards: make(map[string]*wildcardProbe),
	}, nil
}

// Result is the outcome of resolving one hostname.
type Result struct {
	// Rcode is the response code name: NOERROR or NXDOMAIN.
	Rcode string
	// CNAME is the alias chain in resolution order.
	CNAME []string
	A     []netip.Addr
	AAAA  []netip.Addr
}

// Resolved reports whether the name has at least one address.
func (r Result) Resolved() bool {
	return len(r.A)+len(r.AAAA) > 0
}

// Lookup resolves the address records of host. A name that does not exist is
// a valid result, not an error: an error means no resolver gave a usable
// answer, so nothing is known about the name.
func (r *Resolver) Lookup(ctx context.Context, host string) (Result, error) {
	msg, err := r.query(ctx, host, dns.TypeA)
	if err != nil {
		return Result{}, err
	}
	res := Result{Rcode: dns.RcodeToString[msg.Rcode]}
	res.CNAME, res.A = answers(msg)
	if msg.Rcode != dns.RcodeSuccess {
		return res, nil
	}

	msg, err = r.query(ctx, host, dns.TypeAAAA)
	if err != nil {
		return Result{}, err
	}
	if msg.Rcode == dns.RcodeSuccess {
		cname, addrs := answers(msg)
		res.AAAA = addrs
		if len(res.CNAME) == 0 {
			res.CNAME = cname
		}
	}
	return res, nil
}

// NS returns the name servers zone is delegated to, sorted. It is empty for
// names that are not a zone apex.
func (r *Resolver) NS(ctx context.Context, zone string) ([]string, error) {
	msg, err := r.query(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			out = append(out, canonical(ns.Ns))
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// query sends one question, moving on to the next server after a transport
// error or a response that says more about the resolver than about the name.
func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(1232, false)

	start := r.next.Add(1)
	var lastErr error
	for i := range r.attempts {
		if r.limiter != nil {
			if err := r.limiter.Wait(ctx); err != nil {
				return nil, err
			}
		}

		server := r.servers[(start+uint32(i))%uint32(len(r.servers))]
		resp, err := r.exchange(ctx, m, server)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
		case resp.Rcode == dns.RcodeSuccess, resp.Rcode == dns.RcodeNameError:
			return resp, nil
		default:
			lastErr = fmt.Errorf("%s from %s", rcodeName(resp.Rcode), server)
		}
	}
	return nil, fmt.Errorf("resolve: %s %s: %w", dns.TypeToString[qtype], name, lastErr)
}

func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	resp, _, err := r.udp.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		if resp, _, err = r.tcp.ExchangeContext(ctx, m, server); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func answers(msg *dns.Msg) (cname []string, addrs []netip.Addr) {
	for _, rr := range msg.Answer {
		switch rr := rr.(type) {
		case *dns.CNAME:
			cname = append(cname, canonical(rr.Target))
		case *dns.A:
			if addr, ok := netip.AddrFromSlice(rr.A); ok {
				addrs = append(addrs, addr.Unmap())
			}
		case *dns.AAAA:
			if addr, ok := netip.AddrFromSlice(rr.AAAA); ok {
				addrs = append(addrs, addr)
			}
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	return cname, slices.Compact(addrs)
}

func canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func rcodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}
