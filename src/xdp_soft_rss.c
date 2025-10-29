// clang -O2 -target bpf -c xdp_soft_rss.c -o xdp_soft_rss.o
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __bpf_ntohs
#define __bpf_ntohs(x) __builtin_bswap16(x)
#endif

#ifndef __bpf_htons
#define __bpf_htons(x) __builtin_bswap16(x)
#endif

#ifndef __constant_htons
#define __constant_htons(x) __bpf_htons(x)
#endif

#define MAX_BUCKETS 8
#define FLOW_THRESHOLD 100  // packets per flow before triggering event

struct flow_event {
    __u32 bucket;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u64 packet_count;
};

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} bucket_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64);
} flow_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Fast hash function for flow distribution
static __always_inline __u32 flow_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto) {
    __u32 hash = saddr ^ daddr ^ ((__u32)sport << 16) ^ dport ^ ((__u32)proto << 24);

    // Jenkins mix-like hash
    hash ^= hash >> 16;
    hash *= 0x7feb352d;
    hash ^= hash >> 15;
    hash *= 0x846ca68b;
    hash ^= hash >> 16;

    return hash;
}

SEC("xdp")
int xdp_soft_rss(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = __bpf_ntohs(eth->h_proto);
    __u64 offset = sizeof(*eth);

    // Only handle IPv4 for now
    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + offset;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 sport = 0, dport = 0;
    __u8 proto = ip->protocol;
    offset += ip->ihl * 4;

    // Extract transport layer ports - ensure we have enough space for headers
    if ((void *)(data + offset + sizeof(struct tcphdr)) <= data_end && proto == IPPROTO_TCP) {
        struct tcphdr *th = data + offset;
        sport = th->source;
        dport = th->dest;
    } else if ((void *)(data + offset + sizeof(struct udphdr)) <= data_end && proto == IPPROTO_UDP) {
        struct udphdr *uh = data + offset;
        sport = uh->source;
        dport = uh->dest;
    }

    // Compute flow hash and bucket
    __u32 hash = flow_hash(ip->saddr, ip->daddr, sport, dport, proto);
    __u32 bucket = hash % MAX_BUCKETS;

    // Update per-bucket packet counter
    __u64 *bucket_cnt = bpf_map_lookup_elem(&bucket_counters, &bucket);
    if (bucket_cnt) {
        __sync_fetch_and_add(bucket_cnt, 1);
    }

    // Track per-flow statistics for elephant flow detection
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = sport,
        .dport = dport,
        .proto = proto
    };

    __u64 *flow_cnt = bpf_map_lookup_elem(&flow_counters, &key);
    if (flow_cnt) {
        __sync_fetch_and_add(flow_cnt, 1);

        // Emit event for elephant flows
        if (*flow_cnt % FLOW_THRESHOLD == 0) {
            struct flow_event ev = {
                .bucket = bucket,
                .saddr = ip->saddr,
                .daddr = ip->daddr,
                .sport = sport,
                .dport = dport,
                .proto = proto,
                .packet_count = *flow_cnt
            };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        }
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&flow_counters, &key, &initial_count, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";