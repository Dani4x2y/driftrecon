// Package probe examines HTTP services: it completes a TLS handshake,
// requests the front page and records what the server reveals about itself.
// It only ever asks for the front page, the pages that one redirects to on
// the same service, and the favicon.
package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultTimeout      = 10 * time.Second
	defaultMaxBody      = 2 << 20
	defaultMaxRedirects = 10
	defaultSamples      = 2
	defaultHostRate     = 2

	// maxConnectTimeout bounds the TCP handshake on its own. A filtered port
	// swallows the SYN, and waiting out a full request timeout for each one
	// would dominate the scan.
	maxConnectTimeout = 5 * time.Second
	// maxAddresses is how many addresses of a host are tried before the
	// service is considered unreachable.
	maxAddresses = 3
	// minHostRate is the floor a host limiter is slowed down to.
	minHostRate = 0.1
)

// Limiter throttles outgoing connections. *rate.Limiter satisfies it.
type Limiter interface {
	Wait(ctx context.Context) error
}

// Options configures a Prober.
type Options struct {
	// UserAgent is sent with every request and must identify the tool.
	UserAgent string
	// Timeout bounds each phase of a request: connecting and receiving the
	// response headers, and then receiving the body. It defaults to 10
	// seconds.
	Timeout time.Duration
	// MaxBody is how many bytes of a response body are read. It defaults to
	// 2 MiB.
	MaxBody int64
	// MaxRedirects is how many redirects are followed within one service.
	// It defaults to 10.
	MaxRedirects int
	// Samples is how many times the front page is requested to tell stable
	// features from volatile ones. It defaults to 2.
	Samples int
	// Limiter, when set, is consulted before every connection, across all
	// hosts.
	Limiter Limiter
	// HostRate is the number of connections per second allowed to a single
	// host. It defaults to 2.
	HostRate float64
	// AllowPrivate permits connections to loopback, private and otherwise
	// non-public addresses.
	AllowPrivate bool
	// Roots are the certificate authorities chains are verified against.
	// It defaults to the system roots.
	Roots *x509.CertPool
	// Now defaults to time.Now.
	Now func() time.Time
}

// Prober examines HTTP services. It is safe for concurrent use.
type Prober struct {
	userAgent      string
	timeout        time.Duration
	connectTimeout time.Duration
	maxBody        int64
	maxRedirects   int
	samples        int
	limiter        Limiter
	hostRate       rate.Limit
	allowPrivate   bool
	roots          *x509.CertPool
	now            func() time.Time

	mu    sync.Mutex
	hosts map[string]*rate.Limiter
}

// New returns a Prober.
func New(o Options) (*Prober, error) {
	if o.UserAgent == "" || strings.ContainsAny(o.UserAgent, "\r\n") {
		return nil, errors.New("probe: user agent must be a single non-empty line")
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxBody <= 0 {
		o.MaxBody = defaultMaxBody
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = defaultMaxRedirects
	}
	if o.Samples <= 0 {
		o.Samples = defaultSamples
	}
	if o.HostRate <= 0 {
		o.HostRate = defaultHostRate
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Prober{
		userAgent:      o.UserAgent,
		timeout:        o.Timeout,
		connectTimeout: min(o.Timeout, maxConnectTimeout),
		maxBody:        o.MaxBody,
		maxRedirects:   o.MaxRedirects,
		samples:        o.Samples,
		limiter:        o.Limiter,
		hostRate:       rate.Limit(o.HostRate),
		allowPrivate:   o.AllowPrivate,
		roots:          o.Roots,
		now:            o.Now,
		hosts:          make(map[string]*rate.Limiter),
	}, nil
}

// AllowsPrivate reports whether the prober connects to addresses that are
// not public. Scans made with and without it see different services.
func (p *Prober) AllowsPrivate() bool {
	return p.allowPrivate
}

// The phrases recorded when a service cannot be observed. They are part of
// stored observations and must stay stable.
const (
	ReasonConnect   = "connection failed"
	ReasonTimeout   = "timeout"
	ReasonTLS       = "tls handshake failed"
	ReasonProtocol  = "malformed response"
	ReasonNoAddress = "no public address"
)

// failure is an error that ended an attempt to observe a service, together
// with the phrase it is recorded as.
type failure struct {
	reason string
	err    error
}

func (f *failure) Error() string {
	return f.reason + ": " + f.err.Error()
}

func (f *failure) Unwrap() error {
	return f.err
}

// fail wraps err with the reason for the phase it occurred in. Running out
// of time is reported as such whatever the phase.
func fail(reason string, err error) error {
	var netErr net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		reason = ReasonTimeout
	}
	return &failure{reason: reason, err: err}
}

func reasonOf(err error) string {
	var f *failure
	if errors.As(err, &f) {
		return f.reason
	}
	return ReasonConnect
}

// origin identifies a service.
type origin struct {
	scheme string
	host   string
	port   uint16
}

func (o origin) secure() bool {
	return o.scheme == "https"
}

// authority is the host as it appears in a Host header or URL: the port is
// left out when it is the default for the scheme.
func (o origin) authority() string {
	if o.port == defaultPort(o.scheme) {
		return o.host
	}
	return fmt.Sprintf("%s:%d", o.host, o.port)
}

func defaultPort(scheme string) uint16 {
	if scheme == "https" {
		return 443
	}
	return 80
}

// usable returns the addresses the prober is allowed to connect to.
func (p *Prober) usable(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, addr := range addrs {
		if p.allowPrivate || isPublic(addr) {
			out = append(out, addr)
		}
	}
	return out
}

// rotate returns the addresses in the order the nth sample tries them.
// Samples take turns among the addresses of the first family listed, which
// is how backends that are not alike get noticed. The other family is only
// ever a fallback: on a network without working IPv6 each attempt there
// costs a full connect timeout.
func rotate(addrs []netip.Addr, n int) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	family := 1
	for family < len(addrs) && addrs[family].Is4() == addrs[0].Is4() {
		family++
	}
	out := make([]netip.Addr, 0, len(addrs))
	for i := range family {
		out = append(out, addrs[(n+i)%family])
	}
	return append(out, addrs[family:]...)
}

// connect opens a TCP connection to the service, trying the addresses in
// the order given. Every attempt is subject to rate limiting.
func (p *Prober) connect(ctx context.Context, o origin, addrs []netip.Addr) (net.Conn, error) {
	dialer := net.Dialer{Timeout: p.connectTimeout}

	var lastErr error
	for _, ip := range addrs[:min(len(addrs), maxAddresses)] {
		if err := p.wait(ctx, o.host); err != nil {
			return nil, err
		}
		addr := netip.AddrPortFrom(ip, o.port)
		conn, err := dialer.DialContext(ctx, "tcp", addr.String())
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		lastErr = err
	}
	return nil, fail(ReasonConnect, lastErr)
}

func (p *Prober) wait(ctx context.Context, host string) error {
	if p.limiter != nil {
		if err := p.limiter.Wait(ctx); err != nil {
			return err
		}
	}
	return p.hostLimiter(host).Wait(ctx)
}

func (p *Prober) hostLimiter(host string) *rate.Limiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.hosts[host]
	if !ok {
		l = rate.NewLimiter(p.hostRate, 1)
		p.hosts[host] = l
	}
	return l
}

// slowDown halves the request rate towards a host that asked for it, for
// the remaining lifetime of the prober.
func (p *Prober) slowDown(host string) {
	l := p.hostLimiter(host)
	l.SetLimit(max(l.Limit()/2, minHostRate))
}
