// Simplified XDP RSS program - just distribute packets to buckets
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_BUCKETS 8

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);
} bucket_counters SEC(".maps");

// Simple hash using packet length only (safe)
static __always_inline __u32 simple_hash(__u64 len) {
    __u32 hash = (__u32)len;

    // Simple hash based on packet length
    hash = (hash ^ 61) ^ (hash >> 16);
    hash = hash + (hash << 3);
    hash = hash ^ (hash >> 4);
    hash = hash * 0x27d4eb2d;
    hash = hash ^ (hash >> 15);

    return hash;
}

SEC("xdp")
int xdp_rss_simple(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_len = data_end - data;

    // Simple hash based only on packet length (safe)
    __u32 hash = simple_hash(packet_len);
    __u32 bucket = hash % MAX_BUCKETS;

    // Update per-bucket packet counter
    __u64 *bucket_cnt = bpf_map_lookup_elem(&bucket_counters, &bucket);
    if (bucket_cnt) {
        __sync_fetch_and_add(bucket_cnt, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";