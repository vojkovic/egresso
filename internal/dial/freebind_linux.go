//go:build linux

package dial

import (
	"strings"
	"syscall"
)

const (
	solIPv6      = syscall.SOL_IPV6
	ipv6Freebind = 0x4e // IPV6_FREEBIND; not defined in syscall on all arches
)

func controlFreebind(network, _ string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		if strings.HasSuffix(network, "6") {
			sockErr = syscall.SetsockoptInt(int(fd), solIPv6, ipv6Freebind, 1)
			return
		}
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1)
	})
	if err != nil {
		return err
	}
	return sockErr
}
