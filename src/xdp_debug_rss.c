// Debug version of XDP RSS program
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

#define MAX_BUCKETS 8

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} bucket_counters SEC(".maps");

// Debug counters to track what's happening
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} debug_counters SEC(".maps");

// Debug counter indices
#define DEBUG_TOTAL_PACKETS 0
#define DEBUG_IPV4_PACKETS  1
#define DEBUG_TCP_PACKETS   2
#define DEBUG_UDP_PACKETS   3
#define DEBUG_INVALID_PACKETS 4
#define DEBUG_VALID_TCP_UDP 5

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

    // Increment total packet counter
    __u32 key = DEBUG_TOTAL_PACKETS;
    __u64 *count = bpf_map_lookup_elem(&debug_counters, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // Check basic packet bounds
    if ((void *)(eth + 1) > data_end) {
        key = DEBUG_INVALID_PACKETS;
        count = bpf_map_lookup_elem(&debug_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return XDP_PASS;
    }

    __u16 eth_proto = __bpf_ntohs(eth->h_proto);
    __u64 offset = sizeof(*eth);

    // Only handle IPv4 for now
    if (eth_proto != ETH_P_IP) {
        return XDP_PASS;
    }

    // Increment IPv4 counter
    key = DEBUG_IPV4_PACKETS;
    count = bpf_map_lookup_elem(&debug_counters, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    struct iphdr *ip = data + offset;
    if ((void *)(ip + 1) > data_end) {
        key = DEBUG_INVALID_PACKETS;
        count = bpf_map_lookup_elem(&debug_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return XDP_PASS;
    }

    __u16 sport = 0, dport = 0;
    __u8 proto = ip->protocol;
    offset += ip->ihl * 4;

    // Extract transport layer ports - ensure we have enough space for headers
    if ((void *)(data + offset + sizeof(struct tcphdr)) <= data_end && proto == IPPROTO_TCP) {
        struct tcphdr *th = data + offset;
        sport = th->source;
        dport = th->dest;

        key = DEBUG_TCP_PACKETS;
        count = bpf_map_lookup_elem(&debug_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
    } else if ((void *)(data + offset + sizeof(struct udphdr)) <= data_end && proto == IPPROTO_UDP) {
        struct udphdr *uh = data + offset;
        sport = uh->source;
        dport = uh->dest;

        key = DEBUG_UDP_PACKETS;
        count = bpf_map_lookup_elem(&debug_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
    }

    // Count valid TCP/UDP packets that will be processed
    if (sport != 0 || dport != 0) {
        key = DEBUG_VALID_TCP_UDP;
        count = bpf_map_lookup_elem(&debug_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }

        // Compute flow hash and bucket
        __u32 hash = flow_hash(ip->saddr, ip->daddr, sport, dport, proto);
        __u32 bucket = hash % MAX_BUCKETS;

        // Update per-bucket packet counter
        __u64 *bucket_cnt = bpf_map_lookup_elem(&bucket_counters, &bucket);
        if (bucket_cnt) {
            __sync_fetch_and_add(bucket_cnt, 1);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";