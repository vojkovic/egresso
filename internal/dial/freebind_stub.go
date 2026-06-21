//go:build !linux

package dial

import "syscall"

func controlFreebind(_, _ string, _ syscall.RawConn) error {
	return nil
}
