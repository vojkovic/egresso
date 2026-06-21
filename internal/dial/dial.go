package dial

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

func CanBind(addr netip.Addr) error {
	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}
	ln, err := (&net.ListenConfig{Control: controlFreebind}).Listen(
		context.Background(), network, net.JoinHostPort(addr.String(), "0"),
	)
	if err != nil {
		return err
	}
	return ln.Close()
}

func Dial(ctx context.Context, network string, src netip.Addr, dst string) (net.Conn, error) {
	local, err := bindAddr(network, src)
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{LocalAddr: local, Control: controlFreebind}).DialContext(ctx, network, dst)
}

func bindAddr(network string, src netip.Addr) (net.Addr, error) {
	ip := src.AsSlice()
	switch network {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{IP: ip, Port: 0}, nil
	case "udp", "udp4", "udp6":
		return &net.UDPAddr{IP: ip, Port: 0}, nil
	default:
		return nil, fmt.Errorf("unknown network %q", network)
	}
}
