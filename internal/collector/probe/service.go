package probe

import (
	"context"
	"net/netip"
	"net/url"
	"slices"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// Target is a service to examine.
type Target struct {
	Scheme string
	Host   string
	Port   uint16
	// Addrs are the addresses the host resolved to.
	Addrs []netip.Addr
	// Known marks a service that answered in an earlier scan. Failing to
	// reach it is not believed before a second attempt.
	Known bool
	// InScope reports whether a hostname belongs to the target of the scan.
	// It is used to classify where redirects lead.
	InScope func(host string) bool
}

// Result is the outcome of examining a service.
type Result struct {
	// State is StateLive when the service answered, StateUnreachable when
	// it did not, and StateError when it could not be examined at all.
	State       model.State
	Observation model.ServiceObservation
	// Certs holds the certificates Observation.TLS refers to, leaf first.
	Certs []model.Certificate
}

// Leaf returns the certificate of the service itself, or nil.
func (r Result) Leaf() *model.Certificate {
	if r.Observation.TLS == nil || len(r.Observation.TLS.Chain) == 0 || len(r.Certs) == 0 {
		return nil
	}
	return &r.Certs[0]
}

// Service examines one service. The only error it returns is the context's:
// everything that goes wrong with the service itself is part of the result.
func (p *Prober) Service(ctx context.Context, t Target) (Result, error) {
	o := origin{scheme: t.Scheme, host: t.Host, port: t.Port}
	res := Result{
		State:       model.StateError,
		Observation: model.ServiceObservation{URL: model.ServiceKey(t.Scheme, t.Host, t.Port)},
	}

	addrs := p.usable(t.Addrs)
	if len(addrs) == 0 {
		res.Observation.Error = ReasonNoAddress
		return res, nil
	}

	attempts := 1
	if t.Known {
		attempts = 2
	}

	if o.secure() {
		var err error
		for range attempts {
			if res.Observation.TLS, res.Certs, err = p.handshake(ctx, o, addrs); err == nil {
				break
			}
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
		}
		if err != nil {
			res.State = model.StateUnreachable
			res.Observation.Error = reasonOf(err)
			return res, nil
		}
	}

	var (
		samples []*sample
		err     error
	)
	for range attempts {
		var s *sample
		if s, err = p.sample(ctx, t, o, addrs, 0); err == nil {
			samples = append(samples, s)
			break
		}
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
	}
	if err != nil {
		res.Observation.Error = reasonOf(err)
		// A completed handshake proves that something is listening. A TLS
		// endpoint that does not answer HTTP is still an exposed service
		// with a certificate worth tracking.
		if res.Observation.TLS != nil {
			res.State = model.StateLive
		} else {
			res.State = model.StateUnreachable
		}
		return res, nil
	}

	for i := 1; i < p.samples; i++ {
		s, err := p.sample(ctx, t, o, addrs, i)
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if err != nil {
			// One complete sample describes the service. It just could not
			// be cross-checked.
			break
		}
		samples = append(samples, s)
	}

	first := samples[0]
	obs := first.observation(o)
	for _, s := range samples[1:] {
		obs = merge(obs, s.observation(o))
	}
	obs.URL = res.Observation.URL

	if info := res.Observation.TLS; info != nil {
		obs.TLS = info
		if !sameLeaf(info.Chain[0], samples) {
			// Different connections were handed different certificates, so
			// none of them describes the service.
			obs.TLS = &model.TLS{Version: info.Version, Cipher: info.Cipher, ALPN: info.ALPN}
			obs.Volatile = append(obs.Volatile, "tls")
			slices.Sort(obs.Volatile)
			res.Certs = nil
		}
	}

	if target, ok := first.faviconTarget(o); ok {
		if obs.Favicon, err = p.favicon(ctx, o, addrs, target); err != nil {
			return Result{}, err
		}
	}

	res.State, res.Observation = model.StateLive, obs
	return res, nil
}

func sameLeaf(leaf string, samples []*sample) bool {
	for _, s := range samples {
		for _, seen := range s.leaves {
			if seen != leaf {
				return false
			}
		}
	}
	return true
}

// sample is one walk from the front page to the last response the service
// itself gives.
type sample struct {
	hops []model.Hop
	// last is the final response, at is the URL it was served from.
	last *exchange
	at   *url.URL
	// leaves are the server certificates seen along the way.
	leaves []string
	// icon is the icon declared by the final page, once it was described.
	icon *url.URL
}

// sample requests the front page and follows redirects for as long as they
// stay on the service. A redirect that leads anywhere else is recorded and
// left alone: its target is either a service that is examined in its own
// right or none of the scan's business.
func (p *Prober) sample(ctx context.Context, t Target, o origin, addrs []netip.Addr, n int) (*sample, error) {
	s := &sample{at: &url.URL{Scheme: o.scheme, Host: o.authority(), Path: "/"}}
	visited := make(map[string]bool)

	for {
		target := requestTarget(s.at)
		visited[target] = true

		x, err := p.fetch(ctx, o, addrs, n, target)
		if err != nil {
			return nil, err
		}
		if x.leaf != "" {
			s.leaves = append(s.leaves, x.leaf)
		}

		hop := model.Hop{Status: x.status}
		next := redirectTarget(x, s.at)
		if next != nil {
			hop.Location = locationPattern(next)
			hop.Relation = o.relation(next, t.InScope)
		}
		s.hops = append(s.hops, hop)
		s.last = x

		follow := next != nil && hop.Relation == model.RelSameOrigin &&
			len(s.hops) <= p.maxRedirects && !visited[requestTarget(next)]
		if !follow {
			return s, nil
		}
		s.at = next
	}
}

func (s *sample) observation(o origin) model.ServiceObservation {
	obs := model.ServiceObservation{
		Hops:    s.hops,
		Headers: summarizeHeaders(s.last),
	}
	obs.Page, s.icon = describePage(s.last, s.at, o)
	return obs
}

// faviconTarget decides which icon to ask for, if any. A service that only
// sends its visitors elsewhere has none of its own, and an icon hosted
// elsewhere is not this service's to fetch.
func (s *sample) faviconTarget(o origin) (string, bool) {
	switch {
	case s.last.redirects():
		return "", false
	case s.icon == nil:
		return "/favicon.ico", true
	case o.relation(s.icon, nil) != model.RelSameOrigin:
		return "", false
	}
	return requestTarget(s.icon), true
}
