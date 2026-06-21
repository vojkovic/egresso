package socks5

import (
	"bytes"
	"net"
	"testing"
)

func TestAppendAddrIPv4(t *testing.T) {
	buf, err := appendAddr(nil, "192.0.2.1", 1080)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{atypIPv4, 192, 0, 2, 1, 0x04, 0x38}
	if !bytes.Equal(buf, want) {
		t.Fatalf("got %v, want %v", buf, want)
	}
}

func TestAppendAddrIPv6(t *testing.T) {
	buf, err := appendAddr(nil, "2001:db8::1", 53)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != atypIPv6 {
		t.Fatalf("atyp %x", buf[0])
	}
	if len(buf) != 1+16+2 {
		t.Fatalf("len %d", len(buf))
	}
}

func TestAppendAddrDomain(t *testing.T) {
	buf, err := appendAddr(nil, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{atypDomain, 11}, "example.com"...)
	want = append(want, 0x01, 0xbb)
	if !bytes.Equal(buf, want) {
		t.Fatalf("got %v, want %v", buf, want)
	}
}

func TestReadAddrRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		host string
		port uint16
	}{
		{"192.0.2.1", 1080},
		{"2001:db8::1", 53},
		{"example.com", 443},
	} {
		encoded, err := appendAddr(nil, tc.host, tc.port)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readAddr(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		if got.host != tc.host || got.port != tc.port {
			t.Fatalf("%s:%d: got %+v", tc.host, tc.port, got)
		}
	}
}

func TestParseUDP(t *testing.T) {
	payload := []byte("hello")
	header, err := appendAddr([]byte{0, 0, 0}, "192.0.2.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	pkt := append(header, payload...)

	gotPayload, dst, err := parseUDP(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload %q", gotPayload)
	}
	if dst.host != "192.0.2.1" || dst.port != 80 {
		t.Fatalf("dst %+v", dst)
	}
}

func TestParseUDPBadHeader(t *testing.T) {
	_, _, err := parseUDP([]byte{1, 0, 0})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestWrapUDPRoundTrip(t *testing.T) {
	payload := []byte("response")
	wrapped, err := wrapUDP("2001:db8::1", 443, payload)
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, dst, err := parseUDP(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload %q", gotPayload)
	}
	if dst.host != "2001:db8::1" || dst.port != 443 {
		t.Fatalf("dst %+v", dst)
	}
}

func TestHandshakeNoAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		if err := handshake(server); err != nil {
			t.Errorf("handshake: %v", err)
		}
	}()

	req := []byte{ver, 1, authNone}
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}

	var resp [2]byte
	if _, err := client.Read(resp[:]); err != nil {
		t.Fatal(err)
	}
	if resp[0] != ver || resp[1] != authNone {
		t.Fatalf("response %v", resp)
	}
}

func TestHandshakeAuthRequired(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		done <- handshake(server)
	}()

	req := []byte{ver, 1, 0x02} // username/password, unsupported
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}

	var resp [2]byte
	if _, err := client.Read(resp[:]); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0xff {
		t.Fatalf("response %v", resp)
	}
	if err := <-done; err == nil {
		t.Fatal("expected error")
	}
}
