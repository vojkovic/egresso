# egresso

Rotates outbound IPv4 and IPv6 source addresses from a prefix pool, in the kernel. This is the successor to [http-proxy-ipv6-pool-docker](https://github.com/vojkovic/http-proxy-ipv6-pool-docker).

Egresso attaches a BPF program to a container's cgroup and binds a random address from that container's pool on the way out. The pool is the `egresso.prefixes` label.

## Setup

The prefix must either already be routed to you or you can use NDP proxying but I don't recommend it.

Use `sysctl -w net.ipv4.ip_nonlocal_bind=1` (and the ipv6 equivalent) to allow binding to any address.

```sh
ip -6 route add local 2001:db8::/48 dev eth0
ip -4 route add local 192.0.2.0/24 dev eth0
```

## Config

On each container you want rotated:

```yaml
labels:
  egresso.prefixes: "2001:db8::/48,192.0.2.0/24"
```

Optional: `egresso.host-fallback: "true"` falls back to the host address if the pool has no prefix for that family (default is deny).

## Docker

Docker images are available:
- [GitHub CR](https://github.com/vojkovic/egresso/pkgs/container/egresso)
- [Codeberg CR](https://codeberg.org/vojkovic/-/packages/container/egresso/latest)

```sh
docker run -d --name egresso --restart unless-stopped \
  --privileged --cgroupns=host --pid=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/vojkovic/egresso:latest
```
