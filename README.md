<p align="center">
  <img src="docs/icon.svg" alt="egresso" width="96">
</p>

# egresso

This is the successor to my [http-proxy-ipv6-pool-docker](https://github.com/vojkovic/http-proxy-ipv6-pool-docker), but speaks SOCKS5 and can rotate through both IPv4 and IPv6 source addresses.

## Setup

The prefix must already be routed to you, if you don't you can do hacks like NDP proxying but I don't recommend it.

Do `sysctl -w net.ipv4.ip_nonlocal_bind=1` so you can bind to any address.

Add a `local` to route the whole prefix instead of using individual addresses.


```sh
ip -6 route add local 2001:db8::/48 dev eth0
ip -4 route add local 192.0.2.0/24 dev eth0
```

Egresso will probe each prefix at startup and exits if binding fails.

## Config

- `EGRESSO_PREFIXES`: list of CIDR prefixes for source addresses, e.g. `2001:db8::/48,192.0.2.0/24`

- `EGRESSO_PORT`: Port to listen for SOCKS5 connections (default: `1080`)
- `EGRESSO_HOST`: Bind address for SOCKS5 connection, e.g. `127.0.0.1` or `::1` (default: all interfaces)
- `EGRESSO_HOST_FALLBACK`: Fall back to the host default route when the pool cannot be used (default: `false`)
- `EGRESSO_PREFER_V4`: Tries IPv4 before IPv6 if dualstack (default: `false`)

## Docker

```sh
docker run -d --name egresso --network host \
  -e EGRESSO_PREFIXES="2001:db8::/48,192.0.2.0/24" \
  ghcr.io/vojkovic/egresso:latest
```
