package fingerprint

import (
	"testing"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

func host(dns *model.DNS) model.HostObservation {
	return model.HostObservation{Host: "api.example.com", DNS: dns}
}

func TestDNSLayerIgnoresAddressRotation(t *testing.T) {
	a := Host(host(&model.DNS{Rcode: "NOERROR", A: []string{"198.51.100.10", "198.51.100.11"}}))
	b := Host(host(&model.DNS{Rcode: "NOERROR", A: []string{"198.51.100.77"}}))
	if a.DNS != b.DNS {
		t.Error("addresses within one /24 must share a fingerprint")
	}

	c := Host(host(&model.DNS{Rcode: "NOERROR", AAAA: []string{"2001:db8:1:aaaa::1"}}))
	d := Host(host(&model.DNS{Rcode: "NOERROR", AAAA: []string{"2001:db8:1:bbbb::2"}}))
	if c.DNS != d.DNS {
		t.Error("addresses within one /48 must share a fingerprint")
	}
}

func TestDNSLayerDetectsHostingChange(t *testing.T) {
	base := Host(host(&model.DNS{Rcode: "NOERROR", A: []string{"198.51.100.10"}}))

	changed := map[string]*model.DNS{
		"other network": {Rcode: "NOERROR", A: []string{"203.0.113.10"}},
		"extra network": {Rcode: "NOERROR", A: []string{"198.51.100.10", "203.0.113.10"}},
		"moved to ipv6": {Rcode: "NOERROR", AAAA: []string{"2001:db8::1"}},
		"now a cname":   {Rcode: "NOERROR", CNAME: []string{"edge.cdn.example.net"}, A: []string{"198.51.100.10"}},
		"nxdomain":      {Rcode: "NXDOMAIN"},
		"new ns":        {Rcode: "NOERROR", A: []string{"198.51.100.10"}, NS: []string{"ns1.example.net"}},
	}
	for name, dns := range changed {
		if got := Host(host(dns)); got.DNS == base.DNS {
			t.Errorf("%s: fingerprint did not change", name)
		}
	}
}

func TestDNSLayerWithCNAME(t *testing.T) {
	a := Host(host(&model.DNS{Rcode: "NOERROR", CNAME: []string{"edge.cdn.example.net"}, A: []string{"198.51.100.10"}}))
	b := Host(host(&model.DNS{Rcode: "NOERROR", CNAME: []string{"edge.cdn.example.net"}, A: []string{"203.0.113.99"}}))
	if a.DNS != b.DNS {
		t.Error("addresses behind an unchanged CNAME must not affect the fingerprint")
	}

	c := Host(host(&model.DNS{Rcode: "NOERROR", CNAME: []string{"edge.other-cdn.example.org"}, A: []string{"198.51.100.10"}}))
	if a.DNS == c.DNS {
		t.Error("a new CNAME target must change the fingerprint")
	}

	dangling := Host(host(&model.DNS{Rcode: "NXDOMAIN", CNAME: []string{"edge.cdn.example.net"}}))
	if a.DNS == dangling.DNS {
		t.Error("a CNAME that stopped resolving must change the fingerprint")
	}
}

func TestDNSLayerIsOrderIndependent(t *testing.T) {
	a := Host(host(&model.DNS{
		Rcode: "NOERROR",
		A:     []string{"203.0.113.1", "198.51.100.1"},
		NS:    []string{"ns2.example.net", "ns1.example.net"},
	}))
	b := Host(host(&model.DNS{
		Rcode: "NOERROR",
		A:     []string{"198.51.100.1", "203.0.113.1"},
		NS:    []string{"ns1.example.net", "ns2.example.net"},
	}))
	if a.DNS != b.DNS {
		t.Error("record order must not affect the fingerprint")
	}
}

func TestFieldFramingIsUnambiguous(t *testing.T) {
	a := Host(host(&model.DNS{Rcode: "NOERROR", CNAME: []string{"a.example.net", "b.example.net"}}))
	b := Host(host(&model.DNS{Rcode: "NOERROR", CNAME: []string{"a.example.net\n13:b.example.net"}}))
	if a.DNS == b.DNS {
		t.Error("two values hashed the same as one crafted value")
	}
}

func TestUnobservedLayerIsEmpty(t *testing.T) {
	l := Host(host(nil))
	if l.DNS != "" {
		t.Errorf("DNS layer = %q, want empty for an unresolved observation", l.DNS)
	}
	if l.Composite() == "" {
		t.Error("composite fingerprint must always be set")
	}
	if l.Composite() == Host(host(&model.DNS{Rcode: "NOERROR"})).Composite() {
		t.Error("composite must differ once a layer is observed")
	}
}

// The expected values pin the canonical form. If this test fails without an
// intentional change to a layer, the change would report false drift for
// every stored asset. An intentional change needs a Version bump as well.
func TestCanonicalFormIsPinned(t *testing.T) {
	l := Host(host(&model.DNS{
		Rcode: "NOERROR",
		A:     []string{"198.51.100.10"},
		AAAA:  []string{"2001:db8::1"},
		NS:    []string{"ns1.example.net"},
	}))

	const (
		wantDNS       = "c91536fe0391f72b0124343d2f4beb73c37efdd14dc6fcd7667a0718099280e7"
		wantComposite = "cdd8342d32c685e396823d01ef53a2103328396be11bc8ac0763f09ba601008d"
	)
	if l.DNS != wantDNS {
		t.Errorf("dns layer = %s, want %s", l.DNS, wantDNS)
	}
	if got := l.Composite(); got != wantComposite {
		t.Errorf("composite = %s, want %s", got, wantComposite)
	}
}
