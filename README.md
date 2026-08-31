<p align="center">
  <img src="docs/icon.svg" alt="egresso" width="128">
</p>

# egresso

Rotates outbound IPv4 and IPv6 source addresses from a prefix pool, in the kernel. This is the successor to [http-proxy-ipv6-pool-docker](https://github.com/vojkovic/http-proxy-ipv6-pool-docker).

Egresso attaches a BPF program to a container's cgroup and binds a random address from the pool on the way out. Label the container `egresso=true`.

## Setup

The prefix must either already be routed to you or you can use NDP proxying but I don't recommend it.

Use `sysctl -w net.ipv4.ip_nonlocal_bind=1` (and the ipv6 equivalent) to allow binding to any address.

```sh
ip -6 route add local 2001:db8::/48 dev eth0
ip -4 route add local 192.0.2.0/24 dev eth0
```

## Config

- `EGRESSO_PREFIXES`: list of CIDR prefixes for source addresses, e.g. `2001:db8::/48,192.0.2.0/24`

- `EGRESSO_HOST_FALLBACK`: Fallback to the host networking if the pool cannot be used (default: `false`)

On each container you want rotated:

```yaml
labels:
  egresso: "true"
```

## Docker

Docker images are available:
- [GitHub CR](https://github.com/vojkovic/egresso/pkgs/container/egresso)
- [Codeberg CR](https://codeberg.org/vojkovic/-/packages/container/egresso/latest)

It needs the host cgroup hierarchy and a Docker socket so it can find labeled containers.

```sh
docker run -d --name egresso --restart unless-stopped \
  --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e EGRESSO_PREFIXES="2001:db8::/48,192.0.2.0/24" \
  ghcr.io/vojkovic/egresso:latest
```
