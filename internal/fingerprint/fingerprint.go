// Package fingerprint reduces observations to stable hashes, one per layer,
// so that drift can be detected without comparing raw documents.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"net/netip"
	"slices"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

// Version identifies the canonicalisation rules. It must be bumped whenever
// the input of any layer changes: fingerprints produced under different
// versions are not comparable.
const Version = 1

// Layers holds one hash per observed layer. A layer that was not observed is
// left empty.
type Layers struct {
	DNS      string
	TLS      string
	Headers  string
	Redirect string
	DOM      string
}

// Composite folds all layers into the single fingerprint used to decide
// whether an asset changed at all.
func (l Layers) Composite() string {
	d := newDigest("composite")
	d.field("dns", l.DNS)
	// The service layers only enter the hash when they were observed, which
	// keeps the fingerprint of a host independent of them.
	for _, layer := range []struct{ name, hash string }{
		{"tls", l.TLS},
		{"headers", l.Headers},
		{"redirect", l.Redirect},
		{"dom", l.DOM},
	} {
		if layer.hash != "" {
			d.field(layer.name, layer.hash)
		}
	}
	return d.sum()
}

// Host fingerprints a host observation.
func Host(obs model.HostObservation) Layers {
	return Layers{DNS: dnsLayer(obs.DNS)}
}

func dnsLayer(dns *model.DNS) string {
	if dns == nil {
		return ""
	}
	d := newDigest("dns")
	d.field("rcode", dns.Rcode)
	d.field("cname", dns.CNAME...)
	d.field("ns", sorted(dns.NS)...)
	// A CNAME target already names the hosting provider. The addresses behind
	// it belong to that provider and rotate freely, so they only count for
	// names that are served by address records directly.
	if len(dns.CNAME) == 0 {
		d.field("net", networks(dns.A, dns.AAAA)...)
	}
	return d.sum()
}

// networks collapses addresses to their /24 and /48 prefixes. Round-robin
// pools hand out different addresses on every lookup, while the covering
// prefix only moves when the hosting changes.
func networks(groups ...[]string) []string {
	var out []string
	for _, group := range groups {
		for _, s := range group {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				continue
			}
			bits := 24
			if addr.Is6() {
				bits = 48
			}
			prefix, err := addr.Prefix(bits)
			if err != nil {
				continue
			}
			out = append(out, prefix.String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func sorted(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return out
}

type digest struct {
	h hash.Hash
}

func newDigest(layer string) *digest {
	d := &digest{h: sha256.New()}
	fmt.Fprintf(d.h, "driftrecon/%s/v%d\n", layer, Version)
	return d
}

// field frames every value with its length, so that two adjacent values can
// never hash the same as one longer value.
func (d *digest) field(name string, values ...string) {
	fmt.Fprintf(d.h, "%s:%d\n", name, len(values))
	for _, v := range values {
		fmt.Fprintf(d.h, "%d:%s\n", len(v), v)
	}
}

func (d *digest) sum() string {
	return hex.EncodeToString(d.h.Sum(nil))
}
