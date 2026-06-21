package main

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"log"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"

	"github.com/vojkovic/egresso/internal/config"
	"github.com/vojkovic/egresso/internal/pool"
	"github.com/vojkovic/egresso/internal/socks5"
	"github.com/vojkovic/egresso/internal/validate"
)

func main() {
	log := log.New(os.Stderr, "", log.LstdFlags)

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	rng, err := seedRand()
	if err != nil {
		log.Fatal(err)
	}

	p, err := pool.New(cfg.Prefixes, rng)
	if err != nil {
		log.Fatal(err)
	}

	if err := validate.Prefixes(p); err != nil {
		log.Fatalf("prefix check failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("%d prefix(es) ok", len(cfg.Prefixes))
	if cfg.HostFallback {
		log.Print("host fallback enabled")
	}
	if cfg.PreferV4 {
		log.Print("IPv4 preferred on dual-stack")
	}

	if err := socks5.New(p, cfg.Listen(), cfg.HostFallback, cfg.PreferV4, log).Serve(ctx); err != nil {
		log.Fatal(err)
	}
}

func seedRand() (*rand.Rand, error) {
	var seed1, seed2 uint64
	if err := binary.Read(crand.Reader, binary.LittleEndian, &seed1); err != nil {
		return nil, err
	}
	if err := binary.Read(crand.Reader, binary.LittleEndian, &seed2); err != nil {
		return nil, err
	}
	return rand.New(rand.NewPCG(seed1, seed2)), nil
}
