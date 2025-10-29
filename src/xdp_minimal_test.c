// Minimal XDP test - just count everything
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_size SEC(".maps");

SEC("xdp")
int minimal_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_len = data_end - data;

    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    __u64 *size = bpf_map_lookup_elem(&packet_size, &key);
    if (size) {
        __sync_fetch_and_add(size, packet_len);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";