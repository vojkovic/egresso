package pool

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
)

const maxPickAttempts = 16

// skip network/broadcast before giving up

func pick(rng *rand.Rand, prefix netip.Prefix) (netip.Addr, error) {
	for range maxPickAttempts {
		if addr, ok := pickOnce(rng, prefix); ok {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no usable address in %s", prefix)
}

func pickOnce(rng *rand.Rand, prefix netip.Prefix) (netip.Addr, bool) {
	if prefix.Addr().Is4() {
		return pickV4(rng, prefix)
	}
	return pickV6(rng, prefix)
}

func pickV4(rng *rand.Rand, prefix netip.Prefix) (netip.Addr, bool) {
	bits := prefix.Bits()
	o := prefix.Addr().As4()
	base := uint32(o[0])<<24 | uint32(o[1])<<16 | uint32(o[2])<<8 | uint32(o[3])

	hostBits := 32 - bits
	if hostBits <= 0 {
		return prefix.Addr(), true
	}

	mask := uint32(0xffffffff) << hostBits
	host := rng.Uint32() & ^mask
	ip := (base & mask) | host

	if hostBits >= 2 && (host == 0 || host == ^mask) {
		return netip.Addr{}, false
	}

	addr := netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)})
	if !prefix.Contains(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}

func pickV6(rng *rand.Rand, prefix netip.Prefix) (netip.Addr, bool) {
	bits := prefix.Bits()
	hostBits := 128 - bits
	if hostBits <= 0 {
		return prefix.Addr(), true
	}

	base := prefix.Addr().As16()
	var out [16]byte
	copy(out[:], base[:])

	start := 16 - (hostBits+7)/8
	for i := start; i < 16; i++ {
		out[i] = byte(rng.IntN(256))
	}
	if rem := hostBits % 8; rem != 0 {
		mask := byte(0xff << (8 - rem))
		out[start] = (base[start] & mask) | (out[start] & ^mask)
	}

	addr := netip.AddrFrom16(out)
	if !prefix.Contains(addr) || addr.IsMulticast() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}
