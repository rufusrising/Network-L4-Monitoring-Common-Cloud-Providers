// SPDX-License-Identifier: GPL-2.0
//
// L4Scope CO-RE eBPF program. Compiled by the crate's build.rs (clang -target
// bpf) into an object embedded by the `ebpf` capture backend and loaded with
// aya. Attaches to TC clsact (ingress + egress) and pushes fixed-size l4_event
// records into a ring buffer. Only L4 headers are read — no payload is copied.
//
// Requires a generated vmlinux.h (bpftool btf dump ... format c > bpf/vmlinux.h)
// and libbpf headers (libbpf-dev).

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef ETH_P_IP
#define ETH_P_IP   0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

// Mirrors BpfL4Event in crates/l4scope-capture/src/ebpf.rs (field order + sizes).
struct l4_event {
    __u64 ts_nanos;
    __u8  saddr[16];
    __u8  daddr[16];
    __u16 sport;
    __u16 dport;
    __u32 seq;
    __u32 ack;
    __u32 window;
    __u32 payload_len;
    __u8  family;
    __u8  proto;
    __u8  flags;
    __u8  ttl;
    __u32 iface;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

static __always_inline int emit_l4(struct __sk_buff *skb, void *l4, void *data_end,
                                   __u8 proto, __u16 tot_payload,
                                   __u8 family, __u8 ttl,
                                   void *saddr, void *daddr, int addr_len)
{
    struct l4_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_nanos = bpf_ktime_get_ns();
    e->family = family;
    e->proto = proto;
    e->ttl = ttl;
    e->iface = skb->ifindex;
    __builtin_memcpy(e->saddr, saddr, addr_len);
    __builtin_memcpy(e->daddr, daddr, addr_len);

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        __u32 doff = tcp->doff * 4;
        e->sport = bpf_ntohs(tcp->source);
        e->dport = bpf_ntohs(tcp->dest);
        e->seq = bpf_ntohl(tcp->seq);
        e->ack = bpf_ntohl(tcp->ack_seq);
        e->window = bpf_ntohs(tcp->window);
        e->flags = ((__u8 *)tcp)[13] & 0x3f;
        e->payload_len = tot_payload > doff ? (tot_payload - doff) : 0;
    } else { // UDP
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
        e->sport = bpf_ntohs(udp->source);
        e->dport = bpf_ntohs(udp->dest);
        __u16 ulen = bpf_ntohs(udp->len);
        e->payload_len = ulen > 8 ? (ulen - 8) : 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int handle(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
            return TC_ACT_OK;
        __u32 ihl = ip->ihl * 4;
        void *l4 = (void *)ip + ihl;
        __u16 tot = bpf_ntohs(ip->tot_len);
        __u16 payload = tot > ihl ? (tot - ihl) : 0;
        emit_l4(skb, l4, data_end, ip->protocol, payload, 4, ip->ttl,
                &ip->saddr, &ip->daddr, 4);
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;
        // Only direct L4 (no extension-header walk in kernel; userspace tolerates).
        __u8 nh = ip6->nexthdr;
        if (nh != IPPROTO_TCP && nh != IPPROTO_UDP)
            return TC_ACT_OK;
        void *l4 = (void *)(ip6 + 1);
        __u16 payload = bpf_ntohs(ip6->payload_len);
        emit_l4(skb, l4, data_end, nh, payload, 6, ip6->hop_limit,
                &ip6->saddr, &ip6->daddr, 16);
    }

    return TC_ACT_OK;
}

SEC("tc")
int l4scope_tc(struct __sk_buff *skb)
{
    return handle(skb);
}
