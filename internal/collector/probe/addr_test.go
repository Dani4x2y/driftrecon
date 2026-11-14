package probe

import (
	"net/netip"
	"slices"
	"testing"
)

func TestIsPublic(t *testing.T) {
	public := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"172.15.255.255",
		"172.32.0.1",
		"100.63.255.255",
		"100.128.0.1",
		"2606:4700:4700::1111",
		"2a00:1450:4001:80b::200e",
		"::ffff:8.8.8.8",
	}
	for _, s := range public {
		if !isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s was refused", s)
		}
	}

	other := []string{
		"127.0.0.1",
		"127.255.255.254",
		"10.0.0.5",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.169.254",
		"100.64.0.1",
		"100.127.255.255",
		"0.0.0.0",
		"0.1.2.3",
		"192.0.0.8",
		"192.0.2.10",
		"198.18.0.1",
		"198.51.100.7",
		"203.0.113.9",
		"224.0.0.1",
		"240.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"fe80::1",
		"fc00::1",
		"fd12:3456:789a::1",
		"ff02::1",
		"2001:db8::1",
		"2002:c0a8:101::1",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",
		"64:ff9b::a00:1",
		"::ffff:127.0.0.1",
		"::ffff:10.1.2.3",
		"::ffff:169.254.169.254",
	}
	for _, s := range other {
		if isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s was accepted", s)
		}
	}

	if isPublic(netip.Addr{}) {
		t.Error("the zero address was accepted")
	}
}

func TestUsableAddresses(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("10.0.0.5"),
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}

	strict, err := New(Options{UserAgent: "driftrecon-test"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{addrs[1], addrs[3]}
	if got := strict.usable(addrs); !slices.Equal(got, want) {
		t.Errorf("usable = %v, want %v", got, want)
	}

	lax, err := New(Options{UserAgent: "driftrecon-test", AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := lax.usable(addrs); !slices.Equal(got, addrs) {
		t.Errorf("usable = %v, want all of %v", got, addrs)
	}
}
