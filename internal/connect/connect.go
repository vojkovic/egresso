package connect

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/vojkovic/egresso/internal/dial"
	"github.com/vojkovic/egresso/internal/pool"
)

func Dial(ctx context.Context, p *pool.Pool, hostFallback, preferV4 bool, host string, port uint16) (net.Conn, error) {
	cands, err := plan(ctx, p, hostFallback, preferV4, host)
	if err != nil {
		return nil, err
	}
	conn, err := raceTCP(ctx, cands, func(ctx context.Context, c candidate) (net.Conn, error) {
		conn, _, err := dialCandidate(ctx, p, c, port, "tcp")
		return conn, err
	})
	if err != nil {
		return nil, fmt.Errorf("connect %s:%d: %w", host, port, err)
	}
	return conn, nil
}

func DialUDP(ctx context.Context, p *pool.Pool, hostFallback, preferV4 bool, host string, port uint16) (net.Conn, netip.Addr, error) {
	cands, err := plan(ctx, p, hostFallback, preferV4, host)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	conn, peer, err := raceUDP(ctx, cands, func(ctx context.Context, c candidate) (net.Conn, netip.Addr, error) {
		return dialCandidate(ctx, p, c, port, "udp")
	})
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("udp %s:%d: %w", host, port, err)
	}
	return conn, peer, nil
}

func plan(ctx context.Context, p *pool.Pool, hostFallback, preferV4 bool, host string) ([]candidate, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return literalCandidates(ip, p, hostFallback)
	}

	v4s, v6s, err := resolveHost(ctx, host, preferV4)
	if err != nil {
		return nil, err
	}
	if err := checkFamilies(v4s, v6s, p, hostFallback); err != nil {
		return nil, err
	}
	return candidates(v4s, v6s, p, hostFallback, preferV4), nil
}

func checkFamilies(v4s, v6s []net.IP, p *pool.Pool, hostFallback bool) error {
	if len(v6s) > 0 && !p.Has6() && !hostFallback {
		return fmt.Errorf("target has IPv6 but no IPv6 prefixes configured")
	}
	if len(v4s) > 0 && !p.Has4() && !hostFallback {
		return fmt.Errorf("target has IPv4 but no IPv4 prefixes configured")
	}
	return nil
}

func literalCandidates(ip netip.Addr, p *pool.Pool, hostFallback bool) ([]candidate, error) {
	slice := ip.AsSlice()
	if ip.Is4() {
		if p.Has4() {
			return []candidate{{ip: slice, pooled: true}}, nil
		}
		if hostFallback {
			return []candidate{{ip: slice, pooled: false}}, nil
		}
		return nil, fmt.Errorf("no IPv4 prefixes")
	}
	if p.Has6() {
		return []candidate{{ip: slice, pooled: true}}, nil
	}
	if hostFallback {
		return []candidate{{ip: slice, pooled: false}}, nil
	}
	return nil, fmt.Errorf("no IPv6 prefixes")
}

func raceTCP(ctx context.Context, cands []candidate, try func(context.Context, candidate) (net.Conn, error)) (net.Conn, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("no addresses to try")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	won := make(chan net.Conn, 1)
	var wg sync.WaitGroup

	for i, c := range cands {
		wg.Add(1)
		go func(c candidate, delay int) {
			defer wg.Done()
			wait(ctx, delay)
			if ctx.Err() != nil {
				return
			}
			conn, err := try(ctx, c)
			if err != nil {
				return
			}
			select {
			case won <- conn:
				cancel()
			case <-ctx.Done():
				conn.Close()
			}
		}(c, i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case conn := <-won:
		return conn, nil
	case <-done:
		return nil, fmt.Errorf("all attempts failed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func raceUDP(ctx context.Context, cands []candidate, try func(context.Context, candidate) (net.Conn, netip.Addr, error)) (net.Conn, netip.Addr, error) {
	if len(cands) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("no addresses to try")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type win struct {
		conn net.Conn
		peer netip.Addr
	}
	won := make(chan win, 1)
	var wg sync.WaitGroup

	for i, c := range cands {
		wg.Add(1)
		go func(c candidate, delay int) {
			defer wg.Done()
			wait(ctx, delay)
			if ctx.Err() != nil {
				return
			}
			conn, peer, err := try(ctx, c)
			if err != nil {
				return
			}
			select {
			case won <- win{conn, peer}:
				cancel()
			case <-ctx.Done():
				conn.Close()
			}
		}(c, i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case w := <-won:
		return w.conn, w.peer, nil
	case <-done:
		return nil, netip.Addr{}, fmt.Errorf("all attempts failed")
	case <-ctx.Done():
		return nil, netip.Addr{}, ctx.Err()
	}
}

func dialCandidate(ctx context.Context, p *pool.Pool, c candidate, port uint16, proto string) (net.Conn, netip.Addr, error) {
	dst := net.JoinHostPort(c.ip.String(), strconv.Itoa(int(port)))
	peer, _ := netip.ParseAddr(c.ip.String())

	fam := "4"
	if isV6(c.ip) {
		fam = "6"
	}

	if c.pooled {
		src, err := p.Pick(isV6(c.ip))
		if err != nil {
			return nil, netip.Addr{}, err
		}
		conn, err := dial.Dial(ctx, proto+fam, src, dst)
		return conn, peer, err
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, proto+fam, dst)
	return conn, peer, err
}

func isV6(ip net.IP) bool {
	return ip.To4() == nil
}
