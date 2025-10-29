// Debug version of XDP RSS program - Fixed for loopback support
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
#define DEBUG_LOOPBACK_PACKETS 6
#define DEBUG_ETHERNET_PACKETS 7

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

    __u64 offset = 0;
    __u16 sport = 0, dport = 0;
    __u8 proto = 0;
    struct iphdr *ip = NULL;
    __u32 is_loopback = 0;

    // Increment total packet counter
    __u32 key = DEBUG_TOTAL_PACKETS;
    __u64 *count = bpf_map_lookup_elem(&debug_counters, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // First, try to parse as Ethernet (most common case)
    {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) <= data_end) {
            __u16 eth_proto = __bpf_ntohs(eth->h_proto);
            offset = sizeof(*eth);

            // Check if this looks like IPv4
            if (eth_proto == ETH_P_IP) {
                ip = data + offset;
                if ((void *)(ip + 1) <= data_end) {
                    proto = ip->protocol;

                    // Count Ethernet packets
                    key = DEBUG_ETHERNET_PACKETS;
                    count = bpf_map_lookup_elem(&debug_counters, &key);
                    if (count) {
                        __sync_fetch_and_add(count, 1);
                    }
                    goto process_ip;
                }
            }
        }
    }

    // If Ethernet parsing failed, try loopback
    if (data_end - data >= sizeof(struct iphdr) + 4) {
        // Check if this could be a loopback IPv4 packet
        // Look for the start of an IP header after 4 bytes
        struct iphdr *test_ip = data + 4;
        if ((void *)(test_ip + 1) <= data_end && test_ip->version == 4) {
            // This looks like an IPv4 packet in loopback format
            is_loopback = 1;
            offset = 4;
            ip = test_ip;
            proto = ip->protocol;

            // Count loopback packets
            key = DEBUG_LOOPBACK_PACKETS;
            count = bpf_map_lookup_elem(&debug_counters, &key);
            if (count) {
                __sync_fetch_and_add(count, 1);
            }
            goto process_ip;
        }
    }

    // If we get here, it's not a packet we can handle
    return XDP_PASS;

process_ip:
    // At this point, 'ip' points to the IP header and 'proto' is set
    if (!ip) {
        key = DEBUG_INVALID_PACKETS;
        count = bpf_map_lookup_elem(&debug_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
        return XDP_PASS;
    }

    // Increment IPv4 counter
    key = DEBUG_IPV4_PACKETS;
    count = bpf_map_lookup_elem(&debug_counters, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // Calculate offset to transport layer
    __u64 transport_offset;
    if (is_loopback) {
        // Loopback packet: transport starts after 4-byte loopback header + IP header
        transport_offset = 4 + (ip->ihl * 4);
    } else {
        // Ethernet packet: transport starts after Ethernet header + IP header
        transport_offset = sizeof(struct ethhdr) + (ip->ihl * 4);
    }

    // Extract transport layer ports - ensure we have enough space for headers
    if ((void *)(data + transport_offset + sizeof(struct tcphdr)) <= data_end && proto == IPPROTO_TCP) {
        struct tcphdr *th = data + transport_offset;
        sport = th->source;
        dport = th->dest;

        key = DEBUG_TCP_PACKETS;
        count = bpf_map_lookup_elem(&debug_counters, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
    } else if ((void *)(data + transport_offset + sizeof(struct udphdr)) <= data_end && proto == IPPROTO_UDP) {
        struct udphdr *uh = data + transport_offset;
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