package config

import (
	"net/netip"
	"testing"
)

func TestListen(t *testing.T) {
	c := Config{Port: 1080}
	if c.Listen() != ":1080" {
		t.Fatalf("got %q", c.Listen())
	}

	c.Host = "127.0.0.1"
	if c.Listen() != "127.0.0.1:1080" {
		t.Fatalf("got %q", c.Listen())
	}

	c.Host = "::1"
	if c.Listen() != "[::1]:1080" {
		t.Fatalf("got %q", c.Listen())
	}
}

func TestParseBool(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", false},
		{"true", true},
		{"1", true},
		{"false", false},
	} {
		got, err := parseBool(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestLoadRequiresPrefixes(t *testing.T) {
	t.Setenv("EGRESSO_PREFIXES", "")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadHost(t *testing.T) {
	t.Setenv("EGRESSO_PREFIXES", "192.0.2.0/24")
	t.Setenv("EGRESSO_HOST", "not-an-ip")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error")
	}

	t.Setenv("EGRESSO_HOST", "10.0.0.1")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "10.0.0.1" {
		t.Fatalf("host %q", cfg.Host)
	}
	if !netip.MustParseAddr(cfg.Host).Is4() {
		t.Fatal("expected ipv4")
	}
}
