package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"sync"

	"github.com/vojkovic/egresso/internal/connect"
	"github.com/vojkovic/egresso/internal/pool"
)

type Server struct {
	pool         *pool.Pool
	log          *log.Logger
	listen       string
	hostFallback bool
	preferV4     bool

	udp     *net.UDPConn
	udpOnce sync.Once
	udpErr  error
}

func New(p *pool.Pool, listen string, hostFallback, preferV4 bool, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	return &Server{pool: p, listen: listen, hostFallback: hostFallback, preferV4: preferV4, log: logger}
}

func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.listen, err)
	}
	defer ln.Close()

	udp, err := s.udpListen()
	if err != nil {
		return err
	}
	go s.serveUDP(ctx, udp)

	go func() {
		<-ctx.Done()
		ln.Close()
		if s.udp != nil {
			s.udp.Close()
		}
	}()

	s.log.Printf("listening on %s", s.listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	if err := handshake(conn); err != nil {
		s.log.Printf("handshake: %v", err)
		return
	}

	req, err := readRequest(conn)
	if err != nil {
		s.log.Printf("request: %v", err)
		return
	}

	switch req.op {
	case cmdConnect:
		s.doConnect(ctx, conn, req.dst)
	case cmdUDPAssociate:
		s.udpAssociate(conn, req.dst)
	default:
		writeReply(conn, repCmdUnsupported, "0.0.0.0", 0)
	}
}

func handshake(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != ver {
		return fmt.Errorf("bad version %d", hdr[0])
	}

	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	if !slices.Contains(methods, authNone) {
		conn.Write([]byte{ver, 0xff})
		return fmt.Errorf("auth required")
	}

	_, err := conn.Write([]byte{ver, authNone})
	return err
}

type request struct {
	op  byte
	dst addr
}

func readRequest(conn net.Conn) (request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return request{}, err
	}
	if hdr[0] != ver {
		return request{}, fmt.Errorf("bad version %d", hdr[0])
	}
	if hdr[2] != 0 {
		return request{}, fmt.Errorf("bad reserved byte")
	}

	dst, err := readAddrTyped(conn, hdr[3])
	if err != nil {
		return request{}, err
	}
	return request{op: hdr[1], dst: dst}, nil
}

func (s *Server) doConnect(ctx context.Context, conn net.Conn, dst addr) {
	remote, err := connect.Dial(ctx, s.pool, s.hostFallback, s.preferV4, dst.host, dst.port)
	if err != nil {
		s.log.Printf("%s:%d: %v", dst.host, dst.port, err)
		writeReply(conn, repUnreachable, "0.0.0.0", 0)
		return
	}
	defer remote.Close()

	if err := writeReply(conn, repOK, "0.0.0.0", 0); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, remote); done <- struct{}{} }()
	<-done
}
