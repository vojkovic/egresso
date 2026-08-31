/* SPDX-License-Identifier: GPL-2.0 OR MIT */

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_IP 0
#define SOL_IPV6 41
#define IP_FREEBIND 15
#define IPV6_FREEBIND 78
#define BPF_MAP_TYPE_ARRAY 2

#define MAX_PREFIXES 16

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef __u16 __be16;
typedef __u32 __be32;

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((always_inline))

#define bpf_htonl(x) __builtin_bswap32(x)

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u32 (*bpf_get_prandom_u32)(void) = (void *)7;
static long (*bpf_setsockopt)(void *ctx, int level, int optname, void *optval, int optlen) =
    (void *)49;
static long (*bpf_bind)(void *ctx, void *addr, int addr_len) = (void *)64;

struct bpf_sock_addr {
    __u32 user_family;
    __u32 user_ip4;
    __u32 user_ip6[4];
    __u32 user_port;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 msg_src_ip4;
    __u32 msg_src_ip6[4];
};

struct sockaddr_in {
    __u16 sin_family;
    __be16 sin_port;
    __be32 sin_addr;
    __u8 sin_zero[8];
};

struct sockaddr_in6 {
    __u16 sin6_family;
    __be16 sin6_port;
    __be32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
};

struct prefix {
    __u8 family;
    __u8 prefix_len;
    __u8 pad[2];
    __u8 addr[16];
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct bpf_map_def SEC("maps") prefixes_v4 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct prefix),
    .max_entries = MAX_PREFIXES,
};

struct bpf_map_def SEC("maps") prefixes_v6 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct prefix),
    .max_entries = MAX_PREFIXES,
};

struct bpf_map_def SEC("maps") n_v4 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") n_v6 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") flags = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

static __always_inline int allow_fallback(void)
{
    __u32 key = 0;
    __u32 *f = bpf_map_lookup_elem(&flags, &key);

    return f && *f;
}

static __always_inline void freebind4(void *ctx)
{
    int one = 1;

    bpf_setsockopt(ctx, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one));
}

static __always_inline void freebind6(void *ctx)
{
    int one = 1;

    bpf_setsockopt(ctx, SOL_IPV6, IPV6_FREEBIND, &one, sizeof(one));
}

static __always_inline int is_lb4(__u32 ip)
{
    return (ip & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000);
}

static __always_inline int is_mcast4(__u32 ip)
{
    return (ip & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000);
}

static __always_inline int is_v4mapped(const __u32 ip6[4])
{
    return ip6[0] == 0 && ip6[1] == 0 && ip6[2] == bpf_htonl(0x0000ffff);
}

static __always_inline int is_lb6(const __u32 ip6[4])
{
    if (ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0 && ip6[3] == bpf_htonl(1))
        return 1;
    return is_v4mapped(ip6) && is_lb4(ip6[3]);
}

static __always_inline int skip4(__u32 ip)
{
    return is_lb4(ip) || is_mcast4(ip) || ip == bpf_htonl(0xffffffff);
}

static __always_inline int skip6(const __u32 ip6[4])
{
    __u32 b0 = bpf_htonl(ip6[0]);

    if (is_lb6(ip6))
        return 1;
    if ((b0 & 0xff000000) == 0xff000000)
        return 1;
    if ((b0 & 0xffc00000) == 0xfe800000)
        return 1;
    if (is_v4mapped(ip6))
        return skip4(ip6[3]);
    return 0;
}

static __always_inline const struct prefix *rand_from(void *nmap, void *pmap)
{
    __u32 z = 0;
    __u32 *n = bpf_map_lookup_elem(nmap, &z);
    __u32 max;
    __u32 i;

    if (!n || !*n)
        return 0;
    max = *n;
    if (max > MAX_PREFIXES)
        max = MAX_PREFIXES;
    i = bpf_get_prandom_u32() % max;
    return bpf_map_lookup_elem(pmap, &i);
}

static __always_inline int fill_v4(const struct prefix *p, __be32 *out)
{
    __u32 bits = p->prefix_len;
    __u32 net = ((__u32)p->addr[0] << 24) | ((__u32)p->addr[1] << 16) | ((__u32)p->addr[2] << 8) |
                (__u32)p->addr[3];
    __u32 host_bits;
    __u32 host_mask;
    __u32 host;
    int i;

    if (bits >= 32) {
        *out = bpf_htonl(net);
        return 0;
    }
    host_bits = 32 - bits;
    host_mask = host_bits == 32 ? 0xffffffffu : ((1u << host_bits) - 1);

    for (i = 0; i < 8; i++) {
        host = bpf_get_prandom_u32() & host_mask;
        if (host_bits < 2 || (host && host != host_mask)) {
            *out = bpf_htonl((net & ~host_mask) | host);
            return 0;
        }
    }
    return -1;
}

static __always_inline __u32 pack_be(__u8 a, __u8 b, __u8 c, __u8 d)
{
    return ((__u32)a << 24) | ((__u32)b << 16) | ((__u32)c << 8) | (__u32)d;
}

static __always_inline __u32 mix_word(__u32 net, __u32 bits, __u32 off)
{
    __u32 host_bits;
    __u32 host_mask;

    if (bits <= off)
        return bpf_get_prandom_u32();
    if (bits >= off + 32)
        return net;
    host_bits = off + 32 - bits;
    if (host_bits > 31)
        return net;
    host_mask = (1u << host_bits) - 1;
    return (net & ~host_mask) | (bpf_get_prandom_u32() & host_mask);
}

static __always_inline int fill_v6(const struct prefix *p, __u8 out[16])
{
    __u32 bits = p->prefix_len;
    __u32 w0, w1, w2, w3;

    if (bits > 128)
        bits = 128;

    w0 = mix_word(pack_be(p->addr[0], p->addr[1], p->addr[2], p->addr[3]), bits, 0);
    w1 = mix_word(pack_be(p->addr[4], p->addr[5], p->addr[6], p->addr[7]), bits, 32);
    w2 = mix_word(pack_be(p->addr[8], p->addr[9], p->addr[10], p->addr[11]), bits, 64);
    w3 = mix_word(pack_be(p->addr[12], p->addr[13], p->addr[14], p->addr[15]), bits, 96);

    out[0] = (__u8)(w0 >> 24);
    out[1] = (__u8)(w0 >> 16);
    out[2] = (__u8)(w0 >> 8);
    out[3] = (__u8)w0;
    out[4] = (__u8)(w1 >> 24);
    out[5] = (__u8)(w1 >> 16);
    out[6] = (__u8)(w1 >> 8);
    out[7] = (__u8)w1;
    out[8] = (__u8)(w2 >> 24);
    out[9] = (__u8)(w2 >> 16);
    out[10] = (__u8)(w2 >> 8);
    out[11] = (__u8)w2;
    out[12] = (__u8)(w3 >> 24);
    out[13] = (__u8)(w3 >> 16);
    out[14] = (__u8)(w3 >> 8);
    out[15] = (__u8)w3;

    if ((out[0] & 0xf0) == 0xf0)
        return -1;
    return 0;
}

static __always_inline int pick_v4(__be32 *out)
{
    const struct prefix *p = rand_from(&n_v4, &prefixes_v4);

    if (!p)
        return -1;
    return fill_v4(p, out);
}

static __always_inline int pick_v6(__u8 out[16])
{
    const struct prefix *p = rand_from(&n_v6, &prefixes_v6);

    if (!p)
        return -1;
    return fill_v6(p, out);
}

static __always_inline void store_v6(__u32 dst[4], const __u8 src[16])
{
    dst[0] = bpf_htonl(pack_be(src[0], src[1], src[2], src[3]));
    dst[1] = bpf_htonl(pack_be(src[4], src[5], src[6], src[7]));
    dst[2] = bpf_htonl(pack_be(src[8], src[9], src[10], src[11]));
    dst[3] = bpf_htonl(pack_be(src[12], src[13], src[14], src[15]));
}

static __always_inline void v4mapped_words(__u32 dst[4], __be32 v4)
{
    dst[0] = 0;
    dst[1] = 0;
    dst[2] = bpf_htonl(0x0000ffff);
    dst[3] = v4;
}

static __always_inline int bind_v4(void *ctx)
{
    struct sockaddr_in sa = {};

    if (pick_v4(&sa.sin_addr) < 0)
        return allow_fallback();
    freebind4(ctx);
    sa.sin_family = AF_INET;
    bpf_bind(ctx, &sa, sizeof(sa));
    return 1;
}

static __always_inline int bind_v6(void *ctx)
{
    struct sockaddr_in6 sa = {};

    if (pick_v6(sa.sin6_addr) < 0)
        return allow_fallback();
    freebind6(ctx);
    sa.sin6_family = AF_INET6;
    bpf_bind(ctx, &sa, sizeof(sa));
    return 1;
}

static __always_inline int bind_v4mapped(void *ctx)
{
    struct sockaddr_in6 sa = {};
    __be32 v4;

    if (pick_v4(&v4) < 0)
        return allow_fallback();
    freebind6(ctx);
    sa.sin6_family = AF_INET6;
    sa.sin6_addr[10] = 0xff;
    sa.sin6_addr[11] = 0xff;
    sa.sin6_addr[12] = (__u8)v4;
    sa.sin6_addr[13] = (__u8)(v4 >> 8);
    sa.sin6_addr[14] = (__u8)(v4 >> 16);
    sa.sin6_addr[15] = (__u8)(v4 >> 24);
    bpf_bind(ctx, &sa, sizeof(sa));
    return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    if (skip4(ctx->user_ip4))
        return 1;
    return bind_v4(ctx);
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
    if (skip6(ctx->user_ip6))
        return 1;
    if (is_v4mapped(ctx->user_ip6))
        return bind_v4mapped(ctx);
    return bind_v6(ctx);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
    __be32 addr;

    if (skip4(ctx->user_ip4))
        return 1;
    if (pick_v4(&addr) < 0)
        return allow_fallback();
    ctx->msg_src_ip4 = addr;
    return 1;
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
    __u8 addr[16];

    if (skip6(ctx->user_ip6))
        return 1;
    if (is_v4mapped(ctx->user_ip6)) {
        __be32 v4;

        if (pick_v4(&v4) < 0)
            return allow_fallback();
        v4mapped_words(ctx->msg_src_ip6, v4);
        return 1;
    }
    if (pick_v6(addr) < 0)
        return allow_fallback();
    store_v6(ctx->msg_src_ip6, addr);
    return 1;
}

SEC("cgroup/bind4")
int bind4(struct bpf_sock_addr *ctx)
{
    __be32 addr;

    if (ctx->user_ip4)
        return 1;
    if (pick_v4(&addr) < 0)
        return allow_fallback();
    freebind4(ctx);
    ctx->user_ip4 = addr;
    return 1;
}

SEC("cgroup/bind6")
int bind6(struct bpf_sock_addr *ctx)
{
    __u8 addr[16];

    if (ctx->user_ip6[0] || ctx->user_ip6[1] || ctx->user_ip6[2] || ctx->user_ip6[3])
        return 1;
    if (pick_v6(addr) < 0)
        return allow_fallback();
    freebind6(ctx);
    store_v6(ctx->user_ip6, addr);
    return 1;
}

char _license[] SEC("license") = "Dual MIT/GPL";
