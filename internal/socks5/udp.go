package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/vojkovic/egresso/internal/connect"
)

const udpIdle = 30 * time.Second

// read deadline while waiting for client packets

func (s *Server) udpListen() (*net.UDPConn, error) {
	s.udpOnce.Do(func() {
		host, port, err := net.SplitHostPort(s.listen)
		if err != nil {
			s.udpErr = err
			return
		}
		if host == "" {
			host = "0.0.0.0"
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		if err != nil {
			s.udpErr = err
			return
		}
		s.udp, s.udpErr = net.ListenUDP("udp", addr)
	})
	return s.udp, s.udpErr
}

func (s *Server) serveUDP(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		if ctx.Err() != nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(udpIdle))
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n < 4 {
			continue
		}

		payload, dst, err := parseUDP(buf[:n])
		if err != nil {
			continue
		}
		go s.relayUDP(conn, client, payload, dst)
	}
}

func (s *Server) udpAssociate(conn net.Conn, dst addr) {
	udp, err := s.udpListen()
	if err != nil {
		writeReply(conn, repFail, "0.0.0.0", 0)
		return
	}

	host, portStr, _ := net.SplitHostPort(udp.LocalAddr().String())
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
		if ip := net.ParseIP(dst.host); ip != nil && ip.To4() == nil {
			host = "::1"
		}
	}
	port, _ := net.LookupPort("udp", portStr)

	if err := writeReply(conn, repOK, host, uint16(port)); err != nil {
		return
	}
	io.Copy(io.Discard, conn)
}

func parseUDP(pkt []byte) ([]byte, addr, error) {
	if len(pkt) < 4 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		return nil, addr{}, fmt.Errorf("bad udp header")
	}

	r := &pktReader{buf: pkt[3:]}
	dst, err := readAddr(r)
	if err != nil {
		return nil, addr{}, err
	}
	return r.rest(), dst, nil
}

type pktReader struct {
	buf []byte
	off int
}

func (r *pktReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

func (r *pktReader) rest() []byte {
	return r.buf[r.off:]
}

func (s *Server) relayUDP(relay *net.UDPConn, client *net.UDPAddr, payload []byte, dst addr) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, peer, err := connect.DialUDP(ctx, s.pool, s.hostFallback, s.preferV4, dst.host, dst.port)
	if err != nil {
		return
	}
	defer conn.Close()

	udp := conn.(*net.UDPConn)
	if _, err := udp.Write(payload); err != nil {
		return
	}

	udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 64*1024)
	n, err := udp.Read(resp)
	if err != nil {
		return
	}

	out, err := wrapUDP(peer.String(), dst.port, resp[:n])
	if err != nil {
		return
	}
	relay.WriteToUDP(out, client)
}

func wrapUDP(host string, port uint16, payload []byte) ([]byte, error) {
	out := []byte{0, 0, 0}
	out, err := appendAddr(out, host, port)
	if err != nil {
		return nil, err
	}
	return append(out, payload...), nil
}
