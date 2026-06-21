package pool

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
)

type Pool struct {
	v4       []netip.Prefix
	v6       []netip.Prefix
	prefixes []netip.Prefix
	rng      *rand.Rand
}

func New(prefixes []netip.Prefix, rng *rand.Rand) (*Pool, error) {
	p := &Pool{
		rng:      rng,
		prefixes: append([]netip.Prefix(nil), prefixes...),
	}
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			p.v4 = append(p.v4, prefix)
		} else {
			p.v6 = append(p.v6, prefix)
		}
	}
	if len(p.v4) == 0 && len(p.v6) == 0 {
		return nil, fmt.Errorf("no prefixes")
	}
	return p, nil
}

func (p *Pool) Prefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), p.prefixes...)
}

func (p *Pool) Has4() bool { return len(p.v4) > 0 }
func (p *Pool) Has6() bool { return len(p.v6) > 0 }

func (p *Pool) Pick(ipv6 bool) (netip.Addr, error) {
	if ipv6 {
		if len(p.v6) == 0 {
			return netip.Addr{}, fmt.Errorf("no IPv6 prefixes")
		}
		return pick(p.rng, p.v6[p.rng.IntN(len(p.v6))])
	}
	if len(p.v4) == 0 {
		return netip.Addr{}, fmt.Errorf("no IPv4 prefixes")
	}
	return pick(p.rng, p.v4[p.rng.IntN(len(p.v4))])
}

func (p *Pool) PickFrom(prefix netip.Prefix) (netip.Addr, error) {
	return pick(p.rng, prefix)
}
