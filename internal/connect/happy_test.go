package connect

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"

	"github.com/vojkovic/egresso/internal/pool"
)

func testPool(t *testing.T, prefixes []netip.Prefix) *pool.Pool {
	t.Helper()
	p, err := pool.New(prefixes, rand.New(rand.NewPCG(1, 0)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCandidatesInterleave(t *testing.T) {
	v6s := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}
	v4s := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}

	p := testPool(t, []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/64"),
		netip.MustParsePrefix("192.0.2.0/24"),
	})

	got := candidates(v4s, v6s, p, false, false)
	want := []string{
		"2001:db8::1",
		"192.0.2.1",
		"2001:db8::2",
		"192.0.2.2",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.ip.String() != want[i] || !c.pooled {
			t.Fatalf("[%d] got %v pooled=%v, want %s", i, c.ip, c.pooled, want[i])
		}
	}
}

func TestCandidatesPreferV4(t *testing.T) {
	v6s := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}
	v4s := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}

	p := testPool(t, []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/64"),
		netip.MustParsePrefix("192.0.2.0/24"),
	})

	got := candidates(v4s, v6s, p, false, true)
	want := []string{
		"192.0.2.1",
		"2001:db8::1",
		"192.0.2.2",
		"2001:db8::2",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.ip.String() != want[i] || !c.pooled {
			t.Fatalf("[%d] got %v pooled=%v, want %s", i, c.ip, c.pooled, want[i])
		}
	}
}

func TestCandidatesV4Only(t *testing.T) {
	v4s := []net.IP{net.ParseIP("192.0.2.1")}
	p := testPool(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})

	got := candidates(v4s, nil, p, false, false)
	if len(got) != 1 || !got[0].pooled {
		t.Fatalf("got %+v", got)
	}
}

func TestCandidatesHostFallbackV4(t *testing.T) {
	v6s := []net.IP{net.ParseIP("2001:db8::1")}
	v4s := []net.IP{net.ParseIP("192.0.2.1")}

	p := testPool(t, []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")})

	got := candidates(v4s, v6s, p, true, false)
	if len(got) != 2 {
		t.Fatalf("got %d candidates", len(got))
	}
	if got[0].pooled != true || got[1].pooled != false {
		t.Fatalf("got %+v", got)
	}
	if got[1].ip.String() != "192.0.2.1" {
		t.Fatalf("got %s", got[1].ip)
	}
}

func TestCandidatesHostFallbackV6(t *testing.T) {
	v6s := []net.IP{net.ParseIP("2001:db8::1")}
	v4s := []net.IP{net.ParseIP("192.0.2.1")}

	p := testPool(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})

	got := candidates(v4s, v6s, p, true, false)
	if len(got) != 2 {
		t.Fatalf("got %d candidates", len(got))
	}
	if got[0].pooled != true || got[1].pooled != false {
		t.Fatalf("got %+v", got)
	}
	if got[1].ip.String() != "2001:db8::1" {
		t.Fatalf("got %s", got[1].ip)
	}
}
