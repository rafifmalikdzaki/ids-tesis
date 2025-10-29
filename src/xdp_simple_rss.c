// clang -O2 -target bpf -c xdp_simple_rss.c -o xdp_simple_rss.o
// Simplified XDP program without complex BPF maps (no BTF required)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define MAX_BUCKETS 8
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Simple perf event array for flow events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Simple hash function
static __always_inline __u32 flow_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto) {
    __u32 hash = saddr ^ daddr ^ ((__u32)sport << 16) ^ dport ^ ((__u32)proto << 24);
    hash ^= hash >> 16;
    hash *= 0x7feb352d;
    hash ^= hash >> 15;
    hash *= 0x846ca68b;
    hash ^= hash >> 16;
    return hash;
}

SEC("xdp")
int xdp_simple_rss(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 sport = 0, dport = 0;
    __u8 proto = ip->protocol;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = (void *)ip + ip->ihl * 4;
        if ((void *)(th + 1) <= data_end) {
            sport = th->source;
            dport = th->dest;
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = (void *)ip + ip->ihl * 4;
        if ((void *)(uh + 1) <= data_end) {
            sport = uh->source;
            dport = uh->dest;
        }
    }

    // Calculate bucket and emit simple event
    __u32 hash = flow_hash(ip->saddr, ip->daddr, sport, dport, proto);
    __u32 bucket = hash % MAX_BUCKETS;

    struct {
        __u32 bucket;
        __u32 saddr;
        __u32 daddr;
        __u16 sport;
        __u16 dport;
        __u8 proto;
    } event;

    event.bucket = bucket;
    event.saddr = ip->saddr;
    event.daddr = ip->daddr;
    event.sport = sport;
    event.dport = dport;
    event.proto = proto;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";