package connect

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vojkovic/egresso/internal/pool"
)

const resolutionDelay = 50 * time.Millisecond

// wait for the other family after the preferred one returns first

const attemptDelay = 250 * time.Millisecond

// stagger between connection attempts

type candidate struct {
	ip     net.IP
	pooled bool
}

func wait(ctx context.Context, n int) {
	if n == 0 {
		return
	}
	select {
	case <-time.After(time.Duration(n) * attemptDelay):
	case <-ctx.Done():
	}
}

func resolveHost(ctx context.Context, host string, preferV4 bool) (v4s, v6s []net.IP, err error) {
	type ans struct {
		ips []net.IP
		err error
	}

	v6c := make(chan ans, 1)
	v4c := make(chan ans, 1)

	go func() {
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip6", host)
		v6c <- ans{ips, e}
	}()
	go func() {
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		v4c <- ans{ips, e}
	}()

	first, second := v6c, v4c
	if preferV4 {
		first, second = v4c, v6c
	}

	var firstA, secondA ans
	gotFirst := false

	select {
	case firstA = <-first:
		gotFirst = true
	case secondA = <-second:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	if gotFirst {
		select {
		case secondA = <-second:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	} else {
		if len(secondA.ips) > 0 && secondA.err == nil {
			select {
			case firstA = <-first:
				gotFirst = true
			case <-time.After(resolutionDelay):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		if !gotFirst {
			select {
			case firstA = <-first:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
	}

	var v4a, v6a ans
	if preferV4 {
		v4a, v6a = firstA, secondA
	} else {
		v6a, v4a = firstA, secondA
	}

	if v6a.err == nil {
		v6s = v6a.ips
	}
	if v4a.err == nil {
		for _, ip := range v4a.ips {
			if ip4 := ip.To4(); ip4 != nil {
				v4s = append(v4s, ip4)
			}
		}
	}

	if len(v6s) == 0 && len(v4s) == 0 {
		if v6a.err != nil {
			return nil, nil, v6a.err
		}
		if v4a.err != nil {
			return nil, nil, v4a.err
		}
		return nil, nil, fmt.Errorf("no addresses for %s", host)
	}
	return v4s, v6s, nil
}

func candidates(v4s, v6s []net.IP, p *pool.Pool, hostFallback, preferV4 bool) []candidate {
	var v6c, v4c []candidate

	if p.Has6() {
		for _, ip := range v6s {
			v6c = append(v6c, candidate{ip: ip, pooled: true})
		}
	}
	if p.Has4() {
		for _, ip := range v4s {
			v4c = append(v4c, candidate{ip: ip, pooled: true})
		}
	}

	first, second := v6c, v4c
	if preferV4 {
		first, second = v4c, v6c
	}

	n := len(first)
	if len(second) > n {
		n = len(second)
	}

	var out []candidate
	for i := range n {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}

	if hostFallback && len(v4s) > 0 && (len(v6c) > 0 || !p.Has4()) {
		for _, ip := range v4s {
			out = append(out, candidate{ip: ip, pooled: false})
		}
	}
	if hostFallback && len(v6s) > 0 && (len(v4c) > 0 || !p.Has6()) {
		for _, ip := range v6s {
			out = append(out, candidate{ip: ip, pooled: false})
		}
	}

	return out
}
