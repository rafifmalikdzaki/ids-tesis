#!/usr/bin/env python3
"""
Software RSS Reader for XDP Flow Steering
Receives flow events from XDP program and manages bucket-based flow distribution
"""

import os
import sys
import time
import socket
import struct
import signal
import json
import argparse
from collections import defaultdict, deque
from datetime import datetime

try:
    from bcc import BPF, lib
except ImportError:
    print("Error: BCC not found. Install with: sudo apt-get install python3-bpfcc")
    sys.exit(1)

# BPF program text (embedded for easier deployment)
BPF_TEXT = """
// clang -O2 -target bpf -c xdp_soft_rss.c -o xdp_soft_rss.o
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define MAX_BUCKETS 8
#define FLOW_THRESHOLD 100

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
} events SEC(".maps");

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
int xdp_soft_rss(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    __u64 offset = sizeof(*eth);

    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = data + offset;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 sport = 0, dport = 0;
    __u8 proto = ip->protocol;
    offset += ip->ihl * 4;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = data + offset;
        if ((void *)(th + 1) <= data_end) {
            sport = th->source;
            dport = th->dest;
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = data + offset;
        if ((void *)(uh + 1) <= data_end) {
            sport = uh->source;
            dport = uh->dest;
        }
    }

    __u32 hash = flow_hash(ip->saddr, ip->daddr, sport, dport, proto);
    __u32 bucket = hash % MAX_BUCKETS;

    __u64 *bucket_cnt = bpf_map_lookup_elem(&bucket_counters, &bucket);
    if (bucket_cnt) {
        __sync_fetch_and_add(bucket_cnt, 1);
    }

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
"""


class SoftRSSReader:
    def __init__(self, interface="wlo1", max_buckets=8):
        self.interface = interface
        self.max_buckets = max_buckets
        self.bpf = None
        self.running = False

        # Statistics
        self.bucket_stats = defaultdict(lambda: {'packets': 0, 'flows': 0})
        self.flow_history = defaultdict(deque)
        self.elephant_flows = {}

        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False

    def inet_ntoa(self, addr):
        """Convert integer IP to dotted notation"""
        try:
            return socket.inet_ntoa(struct.pack("<I", addr))
        except:
            return f"0.0.0.{addr}"

    def proto_to_string(self, proto):
        """Convert protocol number to string"""
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return proto_map.get(proto, f'PROTO{proto}')

    def handle_flow_event(self, cpu, data, size):
        """Handle flow events from XDP program"""
        event = self.bpf["events"].event(data)

        src_ip = self.inet_ntoa(event.saddr)
        dst_ip = self.inet_ntoa(event.daddr)
        src_port = socket.ntohs(event.sport) if event.sport else 0
        dst_port = socket.ntohs(event.dport) if event.dport else 0
        proto = self.proto_to_string(event.proto)

        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"

        # Update statistics
        self.bucket_stats[event.bucket]['packets'] += event.packet_count
        self.bucket_stats[event.bucket]['flows'] += 1

        # Track elephant flows
        self.elephant_flows[flow_key] = {
            'bucket': event.bucket,
            'packets': event.packet_count,
            'last_seen': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'proto': proto
        }

        # Store in history (keep last 100 events per bucket)
        self.flow_history[event.bucket].append({
            'timestamp': time.time(),
            'flow_key': flow_key,
            'packets': event.packet_count
        })
        if len(self.flow_history[event.bucket]) > 100:
            self.flow_history[event.bucket].popleft()

        # Print event
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] B{event.bucket} | {event.packet_count:6d} packets | "
              f"{src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})")

    def print_bucket_stats(self):
        """Print current bucket statistics"""
        print(f"\n{'='*80}")
        print(f"BUCKET STATISTICS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")

        total_packets = 0
        total_flows = 0

        for bucket in range(self.max_buckets):
            stats = self.bucket_stats[bucket]
            total_packets += stats['packets']
            total_flows += stats['flows']

            # Calculate rate (packets per second over last 10 seconds)
            recent_events = [e for e in self.flow_history[bucket]
                           if time.time() - e['timestamp'] <= 10]
            rate = len(recent_events) / 10.0 if recent_events else 0

            print(f"Bucket {bucket:2d}: {stats['packets']:8d} packets, "
                  f"{stats['flows']:6d} flows, {rate:6.1f} events/sec")

        print(f"{'='*80}")
        print(f"TOTAL: {total_packets} packets, {total_flows} flows")
        print(f"Elephant flows tracked: {len(self.elephant_flows)}")

    def print_top_flows(self, n=10):
        """Print top elephant flows"""
        if not self.elephant_flows:
            return

        print(f"\n{'='*80}")
        print(f"TOP {n} ELEPHANT FLOWS")
        print(f"{'='*80}")
        print(f"{'Packets':>10} {'Bucket':>8} {'Source':>15} {'Destination':>15} {'Proto':>6}")
        print(f"{'-'*80}")

        # Sort by packet count
        sorted_flows = sorted(self.elephant_flows.items(),
                            key=lambda x: x[1]['packets'], reverse=True)

        for flow_key, flow_info in sorted_flows[:n]:
            src = f"{flow_info['src_ip']}:{flow_info['src_port']}"
            dst = f"{flow_info['dst_ip']}:{flow_info['dst_port']}"
            print(f"{flow_info['packets']:10d} {flow_info['bucket']:8d} "
                  f"{src:>15} {dst:>15} {flow_info['proto']:>6}")

    def save_state(self, filename):
        """Save current state to file"""
        state = {
            'timestamp': time.time(),
            'bucket_stats': dict(self.bucket_stats),
            'elephant_flows': self.elephant_flows,
            'interface': self.interface
        }

        with open(filename, 'w') as f:
            json.dump(state, f, indent=2, default=str)
        print(f"State saved to {filename}")

    def run(self, interval=10, save_state_file=None):
        """Main execution loop"""
        print(f"Starting Soft RSS Reader on interface {self.interface}")
        print(f"Max buckets: {self.max_buckets}")
        print(f"Flow threshold: 100 packets")
        print(f"Press Ctrl+C to stop...")

        try:
            # Load BPF program
            self.bpf = BPF(text=BPF_TEXT)
            fn = self.bpf.load_func("xdp_soft_rss", BPF.XDP)

            # Attach XDP program
            self.bpf.attach_xdp(self.interface, fn, 0)  # 0 = XDP generic

            print(f"XDP program loaded successfully on {self.interface}")

            # Setup perf buffer
            self.bpf["events"].open_perf_buffer(self.handle_flow_event, page_cnt=64)

            self.running = True
            last_stats_time = time.time()
            last_save_time = time.time()

            while self.running:
                # Poll for events (timeout 100ms)
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error polling perf buffer: {e}")
                    time.sleep(0.1)

                current_time = time.time()

                # Print statistics every interval seconds
                if current_time - last_stats_time >= interval:
                    self.print_bucket_stats()
                    self.print_top_flows()
                    last_stats_time = current_time

                # Save state periodically if requested
                if save_state_file and current_time - last_save_time >= 60:
                    self.save_state(save_state_file)
                    last_save_time = current_time

        except Exception as e:
            print(f"Error: {e}")
            return 1

        finally:
            # Cleanup
            if self.bpf:
                try:
                    self.bpf.remove_xdp(self.interface, 0)
                    print(f"XDP program removed from {self.interface}")
                except:
                    pass

        return 0


def main():
    parser = argparse.ArgumentParser(description='Software RSS Reader for XDP Flow Steering')
    parser.add_argument('-i', '--interface', default='wlo1',
                       help='Network interface to monitor (default: wlo1)')
    parser.add_argument('-b', '--buckets', type=int, default=8,
                       help='Number of buckets (default: 8)')
    parser.add_argument('-s', '--stats-interval', type=int, default=10,
                       help='Statistics display interval in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Save state to file')
    parser.add_argument('--load-object', help='Load pre-compiled XDP object file')

    args = parser.parse_args()

    # Check if interface exists
    try:
        os.system(f'ip link show {args.interface} > /dev/null 2>&1')
        if os.system(f'ip link show {args.interface} > /dev/null 2>&1') != 0:
            print(f"Error: Interface {args.interface} not found")
            return 1
    except:
        pass

    reader = SoftRSSReader(args.interface, args.buckets)

    if args.load_object:
        print(f"Note: --load-object option specified but using embedded BPF program")
        print(f"To use pre-compiled object, modify the script to load from file")

    return reader.run(args.stats_interval, args.output)


if __name__ == '__main__':
    sys.exit(main())