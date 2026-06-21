package pool

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

func testRNG(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, 0))
}

func TestPickStaysInPrefix(t *testing.T) {
	rng := testRNG(1)
	for _, cidr := range []string{"192.0.2.0/24", "2001:db8::/48", "10.0.0.0/8"} {
		prefix := netip.MustParsePrefix(cidr)
		for range 100 {
			addr, err := pick(rng, prefix)
			if err != nil {
				t.Fatalf("%s: %v", cidr, err)
			}
			if !prefix.Contains(addr) {
				t.Fatalf("%s contains %s", cidr, addr)
			}
		}
	}
}

func TestPickV4SkipsEdges(t *testing.T) {
	rng := testRNG(42)
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	for range 200 {
		addr, err := pick(rng, prefix)
		if err != nil {
			t.Fatal(err)
		}
		last := addr.As4()[3]
		if last == 0 || last == 255 {
			t.Fatalf("got edge address %s", addr)
		}
	}
}

func TestPoolPickByFamily(t *testing.T) {
	rng := testRNG(7)
	p, err := New([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/64"),
	}, rng)
	if err != nil {
		t.Fatal(err)
	}

	v4, err := p.Pick(false)
	if err != nil || !v4.Is4() {
		t.Fatalf("Pick(false) = %v, %v", v4, err)
	}

	v6, err := p.Pick(true)
	if err != nil || !v6.Is6() || v6.Is4() {
		t.Fatalf("Pick(true) = %v, %v", v6, err)
	}
}
