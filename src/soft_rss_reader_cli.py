#!/usr/bin/env python3
"""
Software RSS Reader for XDP Flow Steering
Reads statistics from already loaded XDP program using bpftool
"""

import os
import sys
import time
import signal
import json
import argparse
import subprocess
from collections import defaultdict
from datetime import datetime

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

    def run_bpftool(self, args):
        """Run bpftool command and return output"""
        try:
            cmd = ['sudo', 'bpftool'] + args
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            return result.stdout.strip(), result.stderr.strip()
        except Exception as e:
            print(f"Error running bpftool: {e}")
            return "", str(e)

    def find_map_id(self, map_name):
        """Find map ID by name"""
        stdout, stderr = self.run_bpftool(['map', 'list'])
        if not stdout:
            return None

        for line in stdout.split('\n'):
            if map_name in line:
                # Extract map ID from line like: "746: percpu_array  name bucket_counters"
                parts = line.split(':')
                if len(parts) > 0:
                    try:
                        return int(parts[0])
                    except ValueError:
                        continue
        return None

    def read_map_values(self, map_id):
        """Read all values from a map"""
        if not map_id:
            return {}

        stdout, stderr = self.run_bpftool(['map', 'dump', 'id', str(map_id), '-j'])
        if not stdout or stderr:
            return {}

        values = {}

        # Try to parse as JSON first
        try:
            import json
            data = json.loads(stdout)

            # Handle per-CPU array format
            for entry in data:
                if 'formatted' in entry:
                    # Use the formatted data - it's already parsed correctly
                    formatted = entry['formatted']
                    key = formatted['key']
                    # Sum all CPU values from formatted data
                    total_value = 0
                    for cpu_value in formatted['values']:
                        if isinstance(cpu_value, dict) and 'value' in cpu_value:
                            total_value += cpu_value['value']
                        elif isinstance(cpu_value, int):
                            total_value += cpu_value
                    values[key] = total_value
                elif 'key' in entry and 'values' in entry:
                    # Handle raw hex values (backup)
                    key = entry['key']
                    if isinstance(key, list):
                        # Convert hex key list to int
                        key = int(''.join(key), 16)

                    # Sum all CPU values
                    total_value = 0
                    for cpu_value in entry['values']:
                        if isinstance(cpu_value, dict) and 'value' in cpu_value:
                            value = cpu_value['value']
                            if isinstance(value, list):
                                # Convert hex list to int
                                total_value += int(''.join(value), 16)
                            elif isinstance(value, int):
                                total_value += value
                    values[key] = total_value
                elif 'key' in entry and 'value' in entry:
                    # Simple format
                    value = entry['value']
                    if isinstance(value, int):
                        values[entry['key']] = value
                    elif isinstance(value, list):
                        # Sum list values
                        values[entry['key']] = sum(v for v in value if isinstance(v, int))

        except json.JSONDecodeError:
            # Fallback to text parsing
            lines = stdout.split('\n')
            for line in lines:
                if '->' in line and 'value:' in line:
                    try:
                        parts = line.split('value:')
                        if len(parts) == 2:
                            key_part = parts[0].strip()
                            value_part = parts[1].strip()

                            # Extract key (first 4 bytes for bucket index)
                            key_bytes = key_part.split(':')[1].strip().split()
                            if len(key_bytes) >= 4:
                                key = int.from_bytes(bytes.fromhex(''.join(key_bytes[:4])), 'little')

                            # Extract value (8 bytes for counter)
                            value_bytes = value_part.split()
                            if len(value_bytes) >= 8:
                                value = int.from_bytes(bytes.fromhex(''.join(value_bytes[:8])), 'little')
                                values[key] = value
                    except:
                        continue

        return values

    def read_bucket_counters(self):
        """Read per-bucket packet counters"""
        map_id = self.find_map_id('bucket_counters')
        if not map_id:
            print("Warning: Could not find bucket_counters map")
            return {}

        return self.read_map_values(map_id)

    def print_stats(self, bucket_counters):
        """Print statistics"""
        # Ensure we have values for all buckets
        for i in range(self.max_buckets):
            if i not in bucket_counters:
                bucket_counters[i] = 0

        total_packets = sum(bucket_counters.values())

        print(f"\n=== RSS Statistics @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
        print(f"Total packets processed: {total_packets:,}")
        print(f"Interface: {self.interface}")

        if total_packets > 0:
            print("\nBucket distribution:")
            for bucket in range(self.max_buckets):
                count = bucket_counters.get(bucket, 0)
                percentage = (count / total_packets) * 100
                bar_length = int(percentage / 2)  # Scale down for display
                bar = '█' * bar_length
                print(f"  Bucket {bucket}: {count:8,} ({percentage:5.1f}%) {bar}")

            # Calculate balance score (0-100%, higher is better)
            if total_packets > 0:
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

        # Check if XDP program is loaded
        stdout, stderr = self.run_bpftool(['prog', 'list'])
        if 'xdp_soft_rss' not in stdout and 'xdp_rss_simple' not in stdout:
            print("Warning: No XDP RSS program found")
            print("Make sure an XDP program is loaded first:")
            print(f"  sudo ip link set dev {self.interface} xdpgeneric obj xdp_rss_simple.o sec xdp")
        else:
            if 'xdp_rss_simple' in stdout:
                print("✓ Found xdp_rss_simple program")
            else:
                print("✓ Found xdp_soft_rss program")

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