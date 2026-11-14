package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Dani4x2y/driftrecon/internal/dnstest"
)

func newResolver(t *testing.T, o Options, servers ...*dnstest.Server) *Resolver {
	t.Helper()
	for _, s := range servers {
		o.Servers = append(o.Servers, s.Addr)
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestNewRequiresServers(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a resolver without servers was accepted")
	}
}

func TestLookupAddresses(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone(
		"www.example.test. 60 IN A 192.0.2.20",
		"www.example.test. 60 IN A 192.0.2.10",
		"www.example.test. 60 IN A 192.0.2.10",
		"www.example.test. 60 IN AAAA 2001:db8::2",
		"www.example.test. 60 IN AAAA 2001:db8::1",
	))
	r := newResolver(t, Options{}, srv)

	res, err := r.Lookup(t.Context(), "www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Rcode != "NOERROR" || !res.Resolved() || len(res.CNAME) != 0 {
		t.Errorf("result = %+v", res)
	}
	if want := addrs("192.0.2.10", "192.0.2.20"); !slices.Equal(res.A, want) {
		t.Errorf("A = %v, want %v", res.A, want)
	}
	if want := addrs("2001:db8::1", "2001:db8::2"); !slices.Equal(res.AAAA, want) {
		t.Errorf("AAAA = %v, want %v", res.AAAA, want)
	}
}

func TestLookupFollowsCNAMEChain(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone(
		"shop.example.test. 60 IN CNAME Edge.CDN.test.",
		"edge.cdn.test. 60 IN CNAME lb-7.cdn.test.",
		"lb-7.cdn.test. 60 IN A 198.51.100.7",
	))
	r := newResolver(t, Options{}, srv)

	res, err := r.Lookup(t.Context(), "shop.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"edge.cdn.test", "lb-7.cdn.test"}; !slices.Equal(res.CNAME, want) {
		t.Errorf("CNAME = %v, want %v", res.CNAME, want)
	}
	if want := addrs("198.51.100.7"); !slices.Equal(res.A, want) {
		t.Errorf("A = %v, want %v", res.A, want)
	}
}

func TestLookupNXDOMAIN(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone("www.example.test. 60 IN A 192.0.2.10"))
	r := newResolver(t, Options{}, srv)

	res, err := r.Lookup(t.Context(), "missing.example.test")
	if err != nil {
		t.Fatalf("a missing name is a result, not an error: %v", err)
	}
	if res.Rcode != "NXDOMAIN" || res.Resolved() {
		t.Errorf("result = %+v", res)
	}
	if n := srv.Queries(); n != 1 {
		t.Errorf("queries = %d, want 1: AAAA is pointless after NXDOMAIN", n)
	}
}

func TestLookupDanglingCNAME(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone(
		"old.example.test. 60 IN CNAME gone.hosting.test.",
	))
	r := newResolver(t, Options{}, srv)

	res, err := r.Lookup(t.Context(), "old.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Rcode != "NXDOMAIN" || res.Resolved() {
		t.Errorf("result = %+v", res)
	}
	if want := []string{"gone.hosting.test"}; !slices.Equal(res.CNAME, want) {
		t.Errorf("CNAME = %v, want %v: the alias must survive so it can be flagged", res.CNAME, want)
	}
}

func TestLookupNameWithoutAddresses(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone(`mail.example.test. 60 IN TXT "v=spf1 -all"`))
	r := newResolver(t, Options{}, srv)

	res, err := r.Lookup(t.Context(), "mail.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Rcode != "NOERROR" || res.Resolved() {
		t.Errorf("result = %+v", res)
	}
}

func TestLookupFailsOverToNextServer(t *testing.T) {
	broken := dnstest.NewZone()
	broken.Fail("www.example.test", dns.RcodeServerFailure)
	bad := dnstest.Start(t, broken)
	good := dnstest.Start(t, dnstest.NewZone("www.example.test. 60 IN A 192.0.2.10"))
	r := newResolver(t, Options{Attempts: 2}, bad, good)

	// Whichever server the rotation starts with, two attempts reach both.
	for range 4 {
		res, err := r.Lookup(t.Context(), "www.example.test")
		if err != nil {
			t.Fatal(err)
		}
		if want := addrs("192.0.2.10"); !slices.Equal(res.A, want) {
			t.Fatalf("A = %v, want %v", res.A, want)
		}
	}
	if bad.Queries() == 0 {
		t.Error("rotation never used the first server")
	}
}

func TestLookupReportsServerFailure(t *testing.T) {
	zone := dnstest.NewZone()
	zone.Fail("www.example.test", dns.RcodeRefused)
	srv := dnstest.Start(t, zone)
	r := newResolver(t, Options{Attempts: 3}, srv)

	if _, err := r.Lookup(t.Context(), "www.example.test"); err == nil {
		t.Fatal("REFUSED from every server must be an error")
	}
	if n := srv.Queries(); n != 3 {
		t.Errorf("queries = %d, want 3 attempts", n)
	}
}

func TestLookupTimesOut(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	r, err := New(Options{Servers: []string{silent.LocalAddr().String()}, Timeout: 50 * time.Millisecond, Attempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup(t.Context(), "www.example.test"); err == nil {
		t.Fatal("a silent server must be an error")
	}
}

func TestLookupHonoursContext(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone("www.example.test. 60 IN A 192.0.2.10"))
	r := newResolver(t, Options{}, srv)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.Lookup(ctx, "www.example.test"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestLookupFallsBackToTCP(t *testing.T) {
	zone := dnstest.NewZone("big.example.test. 60 IN A 192.0.2.10")
	zone.TruncateUDP("big.example.test")
	srv := dnstest.Start(t, zone)
	r := newResolver(t, Options{}, srv)

	res, err := r.Lookup(t.Context(), "big.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if want := addrs("192.0.2.10"); !slices.Equal(res.A, want) {
		t.Errorf("A = %v, want %v", res.A, want)
	}
}

type countingLimiter struct {
	calls atomic.Int64
}

func (l *countingLimiter) Wait(context.Context) error {
	l.calls.Add(1)
	return nil
}

func TestEveryQueryPassesTheLimiter(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone("www.example.test. 60 IN A 192.0.2.10"))
	limiter := new(countingLimiter)
	r := newResolver(t, Options{Limiter: limiter}, srv)

	if _, err := r.Lookup(t.Context(), "www.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.NS(t.Context(), "www.example.test"); err != nil {
		t.Fatal(err)
	}
	if got, want := limiter.calls.Load(), srv.Queries(); got != want {
		t.Errorf("limiter consulted %d times for %d queries", got, want)
	}
}

func TestNS(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone(
		"example.test. 60 IN NS ns2.dns.test.",
		"example.test. 60 IN NS NS1.dns.test.",
		"www.example.test. 60 IN A 192.0.2.10",
	))
	r := newResolver(t, Options{}, srv)

	got, err := r.NS(t.Context(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ns1.dns.test", "ns2.dns.test"}; !slices.Equal(got, want) {
		t.Errorf("NS = %v, want %v", got, want)
	}

	got, err = r.NS(t.Context(), "www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("NS of a host = %v, want none", got)
	}
}

func TestWildcard(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone(
		"example.test. 60 IN A 192.0.2.1",
		"www.example.test. 60 IN A 192.0.2.10",
		"wild.example.test. 60 IN A 192.0.2.1",
		"*.wild.example.test. 60 IN A 192.0.2.99",
		"*.wild.example.test. 60 IN AAAA 2001:db8::99",
		"real.wild.example.test. 60 IN A 192.0.2.50",
		"alias.example.test. 60 IN A 192.0.2.1",
		"*.alias.example.test. 60 IN CNAME parking.hosting.test.",
		"parking.hosting.test. 60 IN A 198.51.100.1",
		"own.alias.example.test. 60 IN CNAME app.hosting.test.",
		"app.hosting.test. 60 IN A 198.51.100.2",
	))
	r := newResolver(t, Options{}, srv)
	ctx := t.Context()

	lookup := func(host string) Result {
		t.Helper()
		res, err := r.Lookup(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	plain, err := r.Wildcard(ctx, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if plain != nil {
		t.Error("a zone without a wildcard record was reported as wildcard")
	}
	if plain.Matches(lookup("www.example.test")) {
		t.Error("nil wildcard matched a result")
	}

	wild, err := r.Wildcard(ctx, "wild.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if wild == nil {
		t.Fatal("wildcard zone was not detected")
	}
	if !wild.Matches(lookup("anything.wild.example.test")) {
		t.Error("a synthesised name must match the wildcard")
	}
	if wild.Matches(lookup("real.wild.example.test")) {
		t.Error("a name with its own address must not match the wildcard")
	}
	if wild.Matches(Result{Rcode: "NXDOMAIN"}) {
		t.Error("an unresolved name must not match the wildcard")
	}

	alias, err := r.Wildcard(ctx, "alias.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !alias.Matches(lookup("whatever.alias.example.test")) {
		t.Error("a synthesised alias must match the wildcard")
	}
	if alias.Matches(lookup("own.alias.example.test")) {
		t.Error("a name with its own alias target must not match the wildcard")
	}
}

func TestWildcardIsProbedOncePerZone(t *testing.T) {
	srv := dnstest.Start(t, dnstest.NewZone("*.wild.example.test. 60 IN A 192.0.2.99"))
	r := newResolver(t, Options{}, srv)

	if _, err := r.Wildcard(t.Context(), "wild.example.test"); err != nil {
		t.Fatal(err)
	}
	before := srv.Queries()
	for range 5 {
		if _, err := r.Wildcard(t.Context(), "wild.example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if after := srv.Queries(); after != before {
		t.Errorf("repeat calls sent %d extra queries", after-before)
	}
}
