#!/usr/bin/env python3
"""
Software RSS Reader for XDP Flow Steering
Reads statistics from already loaded XDP program maps
"""

import os
import sys
import time
import signal
import json
import argparse
import struct
from collections import defaultdict
from datetime import datetime

try:
    from bcc import lib
except ImportError:
    print("Error: BCC not found. Install with: sudo apt-get install python3-bpfcc")
    sys.exit(1)

class SoftRSSReader:
    def __init__(self, interface="wlo1", max_buckets=8, stats_interval=10):
        self.interface = interface
        self.max_buckets = max_buckets
        self.stats_interval = stats_interval
        self.running = True

        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False

    def get_map_fd(self, map_name):
        """Get file descriptor for a BPF map by name"""
        try:
            # Find the XDP program and its maps
            prog_info = lib.bpf_prog_get_next_id(None, 0)
            while prog_info:
                try:
                    prog_fd = lib.bpf_prog_get_fd_by_id(prog_info[0])
                    prog_info_detail = lib.bpf_obj_get_info_by_fd(prog_fd)

                    # Check if this is our XDP program
                    if prog_info_detail and prog_info_detail.get('name') == 'xdp_soft_rss':
                        # Get map IDs for this program
                        map_ids = prog_info_detail.get('map_ids', [])

                        for map_id in map_ids:
                            try:
                                map_fd = lib.bpf_map_get_fd_by_id(map_id)
                                map_info = lib.bpf_obj_get_info_by_fd(map_fd)

                                if map_info and map_info.get('name') == map_name:
                                    print(f"Found map '{map_name}' with fd {map_fd}")
                                    return map_fd
                                lib.bpf_close_object(map_fd)
                            except:
                                continue

                    lib.bpf_close_object(prog_fd)
                except:
                    pass

                prog_info = lib.bpf_prog_get_next_id(prog_info[0], 0)

        except Exception as e:
            print(f"Error finding map '{map_name}': {e}")

        return None

    def read_bucket_counters(self):
        """Read per-bucket packet counters"""
        bucket_map_fd = self.get_map_fd('bucket_counters')
        if not bucket_map_fd:
            return {}

        counters = {}
        for i in range(self.max_buckets):
            try:
                key = struct.pack('I', i)
                value = lib.bpf_map_lookup_elem(bucket_map_fd, key)
                if value:
                    counters[i] = struct.unpack('Q', value)[0]
                else:
                    counters[i] = 0
            except:
                counters[i] = 0

        lib.bpf_close_object(bucket_map_fd)
        return counters

    def read_flow_counters(self):
        """Read flow statistics (sample)"""
        flow_map_fd = self.get_map_fd('flow_counters')
        if not flow_map_fd:
            return {}

        flows = {}
        try:
            # Just read a few sample flows for demonstration
            sample_keys = [b'\x00' * 17]  # Empty key as placeholder
            for key in sample_keys:
                try:
                    value = lib.bpf_map_lookup_elem(flow_map_fd, key)
                    if value:
                        count = struct.unpack('Q', value)[0]
                        flows[key] = count
                except:
                    continue
        except:
            pass

        lib.bpf_close_object(flow_map_fd)
        return flows

    def print_stats(self, bucket_counters):
        """Print statistics"""
        total_packets = sum(bucket_counters.values())

        print(f"\n=== RSS Statistics @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
        print(f"Total packets processed: {total_packets:,}")
        print(f"Interface: {self.interface}")

        if total_packets > 0:
            print("\nBucket distribution:")
            for bucket, count in sorted(bucket_counters.items()):
                percentage = (count / total_packets) * 100
                bar_length = int(percentage / 2)  # Scale down for display
                bar = '█' * bar_length
                print(f"  Bucket {bucket}: {count:8,} ({percentage:5.1f}%) {bar}")

            # Calculate balance score (0-100%, higher is better)
            ideal_per_bucket = total_packets / self.max_buckets
            variance = sum((count - ideal_per_bucket) ** 2 for count in bucket_counters.values())
            balance_score = max(0, 100 - (variance / (total_packets * total_packets)) * 100)
            print(f"\nLoad balance score: {balance_score:.1f}%")
        else:
            print("No packets processed yet")

    def run(self):
        """Main monitoring loop"""
        print(f"Starting Soft RSS Reader on interface {self.interface}")
        print(f"Max buckets: {self.max_buckets}")
        print(f"Stats interval: {self.stats_interval} seconds")
        print("Press Ctrl+C to stop...")

        last_counters = {}

        while self.running:
            try:
                # Read current counters
                current_counters = self.read_bucket_counters()

                # Print statistics
                self.print_stats(current_counters)

                # Calculate and print rates
                if last_counters:
                    print("\nPacket rates (packets/sec):")
                    for bucket in range(self.max_buckets):
                        current = current_counters.get(bucket, 0)
                        last = last_counters.get(bucket, 0)
                        rate = (current - last) / self.stats_interval
                        print(f"  Bucket {bucket}: {rate:.1f}")

                last_counters = current_counters.copy()

                # Wait for next interval
                time.sleep(self.stats_interval)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(1)

        print("\nReader stopped")

def main():
    parser = argparse.ArgumentParser(description='Soft RSS Reader for XDP program')
    parser.add_argument('-i', '--interface', default='wlo1',
                       help='Network interface name (default: wlo1)')
    parser.add_argument('-b', '--buckets', type=int, default=8,
                       help='Number of buckets (default: 8)')
    parser.add_argument('-s', '--stats-interval', type=int, default=10,
                       help='Statistics interval in seconds (default: 10)')
    parser.add_argument('-o', '--output',
                       help='Output file for statistics (JSON format)')

    args = parser.parse_args()

    reader = SoftRSSReader(
        interface=args.interface,
        max_buckets=args.buckets,
        stats_interval=args.stats_interval
    )

    reader.run()

if __name__ == '__main__':
    main()