#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
// #include "vmlinux.h"

// Header cursor to keep track of current parsing position
struct hdr_cursor
{
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    // Check if size of header does not exceed remaining number of bytes to parse.
    if (nh->pos + hdrsize > data_end)
    {
        return -1;
    }

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto; // Network byte order
}

static __always_inline int parse_ipv6hdr(struct hdr_cursor *nh, void *data_end,
                                         struct ipv6hdr **ipv6hdr)
{
    struct ipv6hdr *ipv6h = nh->pos;
    int hdrsize = sizeof(*ipv6h);

    // Check if size of header does not exceed remaining number of bytes to parse.
    if (nh->pos + hdrsize > data_end)
    {
        return -1;
    }

    nh->pos += hdrsize;
    *ipv6hdr = ipv6h;

    return ipv6h->nexthdr;
}

SEC("xdp")
// If both source and destination IPv6 address of a packet
// is a ULA (that begins with fd20), drop the packet if
// the user IDs of two addresses (represented with the 7th quartet)
// are not equal.
int filter_ipv6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct hdr_cursor nh;
    struct ethhdr *eth;
    struct ipv6hdr *ip6h;

    nh.pos = data;

    int protocol = parse_ethhdr(&nh, data_end, &eth);

    if (protocol == bpf_htons(ETH_P_IPV6))
    {
        if (parse_ipv6hdr(&nh, data_end, &ip6h) == -1)
        {
            return XDP_DROP;
        }

        __be16 src_user = ip6h->saddr.s6_addr16[6];  // Network byte order
        __be16 dest_user = ip6h->daddr.s6_addr16[6]; // Network byte order

        bool is_src_ula = bpf_ntohs(ip6h->saddr.s6_addr16[0]) == 0xfd20;
        bool is_dest_ula = bpf_ntohs(ip6h->daddr.s6_addr16[0]) == 0xfd20;

        if (is_src_ula && is_dest_ula && src_user != dest_user)
        {
            bpf_printk("[DROP] src: %pI6 dest: %pI6", ip6h->saddr.s6_addr, ip6h->daddr.s6_addr);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
