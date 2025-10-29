#!/usr/bin/env python3
"""
Fast RSS Reader using direct BPF library calls
"""

import os
import sys
import time
import signal
import json
import argparse
from collections import defaultdict
from datetime import datetime

try:
    from bcc import lib
    from bcc.syscall import bpf_map_get_next_id, bpf_map_get_fd_by_id, bpf_map_lookup_elem, bpf_obj_get_info_by_fd
    from bcc.syscall import bpf_close_object
except ImportError:
    print("Error: BCC not found. Install with: sudo apt-get install python3-bpfcc")
    sys.exit(1)

class FastRSSReader:
    def __init__(self, interface="lo", max_buckets=8, stats_interval=3):
        self.interface = interface
        self.max_buckets = max_buckets
        self.stats_interval = stats_interval
        self.running = True
        self.map_fd = None
        self.map_id = None

        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False

    def find_map_id(self, map_name):
        """Find map ID by name using BCC"""
        try:
            # Get first map ID
            map_id = bpf_map_get_next_id(0)
            while map_id:
                try:
                    map_fd = bpf_map_get_fd_by_id(map_id[0])
                    if map_fd > 0:
                        try:
                            map_info = bpf_obj_get_info_by_fd(map_fd)
                            if map_info and map_info.get('name') == map_name:
                                self.map_id = map_id[0]
                                self.map_fd = map_fd
                                return map_id[0]
                        except:
                            pass
                        finally:
                            bpf_close_object(map_fd)
                    map_id = bpf_map_get_next_id(map_id[0])
                except:
                    break
        except Exception as e:
            print(f"Error finding map: {e}")
        return None

    def read_map_fast(self):
        """Read map values using direct BPF calls"""
        if not self.map_fd:
            return {}

        values = {}
        try:
            for bucket in range(self.max_buckets):
                key = bucket.to_bytes(4, 'little')
                result = bpf_map_lookup_elem(self.map_fd, key)
                if result:
                    # Parse per-CPU values (JSON-like structure from BCC)
                    try:
                        if isinstance(result, bytes):
                            # Convert bytes to list of 8-byte values
                            values_list = []
                            for i in range(0, len(result), 8):
                                if i + 8 <= len(result):
                                    value = int.from_bytes(result[i:i+8], 'little')
                                    values_list.append(value)
                            values[bucket] = sum(values_list)
                        else:
                            values[bucket] = int(result)
                    except:
                        values[bucket] = 0
                else:
                    values[bucket] = 0
        except Exception as e:
            print(f"Error reading map: {e}")

        return values

    def print_stats(self, bucket_counters):
        """Print statistics"""
        total_packets = sum(bucket_counters.values())

        print(f"\n=== RSS Statistics @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
        print(f"Total packets processed: {total_packets:,}")
        print(f"Interface: {self.interface}")

        if total_packets > 0:
            print("\nBucket distribution:")
            for bucket in range(self.max_buckets):
                count = bucket_counters.get(bucket, 0)
                percentage = (count / total_packets) * 100
                bar_length = int(percentage / 2)
                bar = '█' * bar_length
                print(f"  Bucket {bucket}: {count:8,} ({percentage:5.1f}%) {bar}")

            # Calculate balance score
            if total_packets > 0:
                ideal_per_bucket = total_packets / self.max_buckets
                variance = sum((count - ideal_per_bucket) ** 2 for count in bucket_counters.values())
                balance_score = max(0, 100 - (variance / (total_packets * total_packets)) * 100)
                print(f"\nLoad balance score: {balance_score:.1f}%")
        else:
            print("No packets processed yet")

    def run(self):
        """Main monitoring loop"""
        print(f"Starting Fast RSS Reader on interface {self.interface}")
        print(f"Max buckets: {self.max_buckets}")
        print(f"Stats interval: {self.stats_interval} seconds")
        print("Press Ctrl+C to stop...")

        # Find and open the map once
        map_id = self.find_map_id('bucket_counters')
        if not map_id:
            print("Error: Could not find bucket_counters map")
            print("Make sure the XDP program is loaded")
            return

        print(f"✓ Found bucket_counters map (ID: {map_id})")

        last_counters = {}

        while self.running:
            try:
                start_time = time.time()

                # Read counters using fast BPF calls
                current_counters = self.read_map_fast()

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

                # Calculate remaining sleep time to maintain interval
                elapsed = time.time() - start_time
                sleep_time = max(0, self.stats_interval - elapsed)
                time.sleep(sleep_time)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(1)

        # Clean up
        if self.map_fd:
            bpf_close_object(self.map_fd)

        print("\nReader stopped")

def main():
    parser = argparse.ArgumentParser(description='Fast RSS Reader for XDP program')
    parser.add_argument('-i', '--interface', default='lo',
                       help='Network interface name (default: lo)')
    parser.add_argument('-b', '--buckets', type=int, default=8,
                       help='Number of buckets (default: 8)')
    parser.add_argument('-s', '--stats-interval', type=int, default=3,
                       help='Statistics interval in seconds (default: 3)')

    args = parser.parse_args()

    reader = FastRSSReader(
        interface=args.interface,
        max_buckets=args.buckets,
        stats_interval=args.stats_interval
    )

    reader.run()

if __name__ == '__main__':
    main()