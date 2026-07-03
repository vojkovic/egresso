<p align="center">
  <img src="docs/icon.svg" alt="egresso" width="128">
</p>

# egresso

SOCKS5 proxy that can rotate through both IPv4 and IPv6 source addresses. This is the successor to [http-proxy-ipv6-pool-docker](https://github.com/vojkovic/http-proxy-ipv6-pool-docker) 

## Setup

The prefix must either already be routed to you or you can use NDP proxying but I don't recommend it.

Use `sysctl -w net.ipv4.ip_nonlocal_bind=1` to allow binding to any address.

```sh
ip -6 route add local 2001:db8::/48 dev eth0
ip -4 route add local 192.0.2.0/24 dev eth0
```

## Config

- `EGRESSO_PREFIXES`: list of CIDR prefixes for source addresses, e.g. `2001:db8::/48,192.0.2.0/24`

- `EGRESSO_PORT`: Port to listen for SOCKS5 connections (default: `1080`)
- `EGRESSO_HOST`: Bind address for SOCKS5 connection, e.g. `::1` (default: all interfaces)
- `EGRESSO_HOST_FALLBACK`: Fallback to the host networking if the pool cannot be used (default: `false`)
- `EGRESSO_PREFER_V4`: Try IPv4 before IPv6 (default: `false`)

## Docker

Docker images are available:
- [GitHub CR](https://github.com/vojkovic/egresso/pkgs/container/egresso)
- [Codeberg CR](https://codeberg.org/vojkovic/-/packages/container/egresso/latest)

```sh
docker run -d --name egresso --network host \
  -e EGRESSO_PREFIXES="2001:db8::/48,192.0.2.0/24" \
  ghcr.io/vojkovic/egresso:latest
```
