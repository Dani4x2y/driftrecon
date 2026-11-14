package fingerprint

import (
	"cmp"
	"maps"
	"slices"
	"strconv"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// Service fingerprints a service observation. leaf is the certificate at the
// head of the observed chain and may be nil.
func Service(obs model.ServiceObservation, leaf *model.Certificate) Layers {
	return Layers{
		TLS:      tlsLayer(obs.TLS, leaf),
		Headers:  headersLayer(obs.Headers),
		Redirect: redirectLayer(obs.Hops),
		DOM:      domLayer(obs.Page),
	}
}

// tlsLayer covers who vouches for the service and with which key. The serial
// number and the validity dates are deliberately left out: a renewal that
// keeps issuer, key and names is routine and must not look like a change of
// identity.
func tlsLayer(t *model.TLS, leaf *model.Certificate) string {
	if t == nil {
		return ""
	}
	d := newDigest("tls")
	d.field("version", t.Version)
	d.field("alpn", t.ALPN)
	d.field("issues", sorted(t.Issues)...)
	if leaf != nil {
		d.field("issuer", leaf.IssuerOrg, leaf.IssuerCN)
		d.field("spki", leaf.SPKISHA256)
		d.field("key", leaf.KeyAlg)
		d.field("san", sorted(leaf.SANs)...)
	}
	return d.sum()
}

func headersLayer(h *model.Headers) string {
	if h == nil {
		return ""
	}
	d := newDigest("headers")
	d.field("names", h.Names...)
	for _, name := range slices.Sorted(maps.Keys(h.Values)) {
		d.field("value", name, h.Values[name])
	}
	for _, c := range sortedCookies(h.Cookies) {
		d.field("cookie", append([]string{c.Name}, sorted(c.Flags)...)...)
	}
	return d.sum()
}

func sortedCookies(cookies []model.Cookie) []model.Cookie {
	out := slices.Clone(cookies)
	slices.SortStableFunc(out, func(a, b model.Cookie) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

func redirectLayer(hops []model.Hop) string {
	if len(hops) == 0 {
		return ""
	}
	d := newDigest("redirect")
	for _, hop := range hops {
		d.field("hop", strconv.Itoa(hop.Status), string(hop.Relation), hop.Location)
	}
	return d.sum()
}

// domLayer covers the shape of the response body. Documents are compared by
// their skeleton and form signatures. Anything else has no structure to
// speak of and is compared by type and content.
func domLayer(p *model.Page) string {
	switch {
	case p == nil:
		return ""
	case p.Skeleton != "":
		d := newDigest("dom")
		d.field("skeleton", p.Skeleton)
		for _, form := range p.Forms {
			values := []string{form.Method, form.Action}
			for _, f := range form.Fields {
				values = append(values, f.Type, f.Name)
			}
			d.field("form", values...)
		}
		return d.sum()
	case p.SimHash != nil:
		// A document whose skeleton differed between samples has no stable
		// exact form. It is compared by SimHash distance only.
		return ""
	case p.ContentType == "" && p.BodySHA256 == "":
		return ""
	default:
		d := newDigest("dom")
		d.field("type", p.ContentType)
		d.field("body", p.BodySHA256)
		return d.sum()
	}
}
