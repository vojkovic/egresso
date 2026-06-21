package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const envPrefixes = "EGRESSO_PREFIXES"

// comma-separated CIDR list

const envPort = "EGRESSO_PORT"

// listen port, default 1080

const envHost = "EGRESSO_HOST"

// listen address, default all interfaces

const envHostFallback = "EGRESSO_HOST_FALLBACK"

// egress via system default route when the pool cannot

const envPreferV4 = "EGRESSO_PREFER_V4"

// try IPv4 before IPv6 on dual-stack hostnames

const defaultPort = 1080

type Config struct {
	Prefixes     []netip.Prefix
	Port         int
	Host         string
	HostFallback bool
	PreferV4     bool
}

func Load() (Config, error) {
	raw := strings.TrimSpace(os.Getenv(envPrefixes))
	if raw == "" {
		return Config{}, fmt.Errorf("%s is required", envPrefixes)
	}

	var prefixes []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return Config{}, fmt.Errorf("invalid CIDR %q: %w", part, err)
		}
		if !prefix.IsValid() {
			return Config{}, fmt.Errorf("invalid CIDR %q", part)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if len(prefixes) == 0 {
		return Config{}, fmt.Errorf("%s must contain at least one CIDR", envPrefixes)
	}

	port := defaultPort
	if s := strings.TrimSpace(os.Getenv(envPort)); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: %w", envPort, s, err)
		}
		if n < 1 || n > 65535 {
			return Config{}, fmt.Errorf("%s must be between 1 and 65535", envPort)
		}
		port = n
	}

	host := strings.TrimSpace(os.Getenv(envHost))
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: %w", envHost, host, err)
		}
	}

	hostFallback, err := parseBool(os.Getenv(envHostFallback))
	if err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", envHostFallback, err)
	}

	preferV4, err := parseBool(os.Getenv(envPreferV4))
	if err != nil {
		return Config{}, fmt.Errorf("invalid %s: %w", envPreferV4, err)
	}

	return Config{
		Prefixes:     prefixes,
		Port:         port,
		Host:         host,
		HostFallback: hostFallback,
		PreferV4:     preferV4,
	}, nil
}

func (c Config) Listen() string {
	if c.Host == "" {
		return fmt.Sprintf(":%d", c.Port)
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("expected true/false, got %q", s)
	}
}
