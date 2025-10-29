// clang -O2 -target bpf -c xdp_rss_xsk.c -o xdp_rss_xsk.o
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

#define MAX_WORKERS 8

struct flow_event {
  __u32 qid;
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u8 proto;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// simple Jenkins mix hash
static __inline __u32 jhash_mix(__u32 a, __u32 b, __u32 c) {
  a -= b;
  a -= c;
  a ^= (c >> 13);
  b -= c;
  b -= a;
  b ^= (a << 8);
  c -= a;
  c -= b;
  c ^= (b >> 13);
  a -= b;
  a -= c;
  a ^= (c >> 12);
  return a ^ b ^ c;
}

SEC("xdp")
int xdp_soft_rss(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  __u16 proto = __bpf_ntohs(eth->h_proto);
  __u64 offset = sizeof(*eth);
  struct flow_event ev = {};
  __u32 hash = 0;

  if (proto == ETH_P_IP) {
    struct iphdr *ip = data + offset;
    if ((void *)(ip + 1) > data_end)
      return XDP_PASS;
    ev.saddr = ip->saddr;
    ev.daddr = ip->daddr;
    ev.proto = ip->protocol;
    if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr *th = (void *)ip + ip->ihl * 4;
      if ((void *)(th + 1) <= data_end) {
        ev.sport = th->source;
        ev.dport = th->dest;
      }
    } else if (ip->protocol == IPPROTO_UDP) {
      struct udphdr *uh = (void *)ip + ip->ihl * 4;
      if ((void *)(uh + 1) <= data_end) {
        ev.sport = uh->source;
        ev.dport = uh->dest;
      }
    }
    hash = jhash_mix(ev.saddr, ev.daddr,
                     ((__u32)ev.proto << 16) | ev.sport ^ ev.dport);
  } else {
    return XDP_PASS;
  }

  ev.qid = hash % MAX_WORKERS;
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
