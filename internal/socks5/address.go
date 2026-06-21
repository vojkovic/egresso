package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type addr struct {
	host string
	port uint16
}

func readAddr(r io.Reader) (addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return addr{}, err
	}
	return readAddrTyped(r, atyp[0])
}

func readAddrTyped(r io.Reader, atyp byte) (addr, error) {
	var host string

	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return addr{}, err
		}
		host = net.IP(b[:]).String()
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return addr{}, err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return addr{}, err
		}
		host = string(name)
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return addr{}, err
		}
		host = net.IP(b[:]).String()
	default:
		return addr{}, fmt.Errorf("bad address type 0x%02x", atyp)
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return addr{}, err
	}
	return addr{host: host, port: binary.BigEndian.Uint16(port[:])}, nil
}

func appendAddr(buf []byte, host string, port uint16) ([]byte, error) {
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		buf = append(buf, atypIPv4)
		buf = append(buf, ip.To4()...)
	case ip != nil:
		buf = append(buf, atypIPv6)
		buf = append(buf, ip.To16()...)
	default:
		if len(host) > 255 {
			return nil, fmt.Errorf("name too long")
		}
		buf = append(buf, atypDomain, byte(len(host)))
		buf = append(buf, host...)
	}

	var b [2]byte
	binary.BigEndian.PutUint16(b[:], port)
	return append(buf, b[:]...), nil
}

func writeAddr(w io.Writer, host string, port uint16) error {
	buf, err := appendAddr(nil, host, port)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

func writeReply(w io.Writer, rep byte, host string, port uint16) error {
	if host == "" {
		host = "0.0.0.0"
	}
	if _, err := w.Write([]byte{ver, rep, 0}); err != nil {
		return err
	}
	return writeAddr(w, host, port)
}
