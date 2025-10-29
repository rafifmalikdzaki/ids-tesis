#!/usr/bin/env python3
"""
Optimized RSS Reader - faster subprocess version for Arch Linux
"""

import os
import sys
import time
import signal
import json
import subprocess
import argparse
from collections import defaultdict
from datetime import datetime

class OptimizedRSSReader:
    def __init__(self, interface="lo", max_buckets=8, stats_interval=3):
        self.interface = interface
        self.max_buckets = max_buckets
        self.stats_interval = stats_interval
        self.running = True
        self.map_id = None

        # Cache the map lookup command
        self.base_cmd = ['sudo-rs', 'bpftool']

        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False

    def run_bpftool(self, args):
        """Run bpftool command and return output"""
        try:
            cmd = self.base_cmd + args
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
            return result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return "", "Timeout"
        except Exception as e:
            return "", str(e)

    def find_map_id(self, map_name):
        """Find map ID by name"""
        if self.map_id:
            return self.map_id

        stdout, stderr = self.run_bpftool(['map', 'list'])
        if not stdout:
            return None

        for line in stdout.split('\n'):
            if map_name in line:
                parts = line.split(':')
                if len(parts) > 0:
                    try:
                        self.map_id = int(parts[0])
                        return self.map_id
                    except ValueError:
                        continue
        return None

    def read_map_values_optimized(self):
        """Read map values using optimized JSON parsing"""
        if not self.map_id:
            return {}

        # Use JSON output for faster parsing
        stdout, stderr = self.run_bpftool(['map', 'dump', 'id', str(self.map_id), '-j'])
        if not stdout or stderr:
            return {}

        values = {}

        try:
            # Parse JSON directly
            data = json.loads(stdout)

            for entry in data:
                if 'formatted' in entry:
                    # Use the formatted data - it's already parsed correctly
                    formatted = entry['formatted']
                    key = formatted['key']
                    # Sum all CPU values from formatted data
                    total_value = sum(cpu_value['value'] for cpu_value in formatted['values'])
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

        except json.JSONDecodeError:
            # Fallback: simple text parsing (faster than full JSON)
            lines = stdout.split('\n')
            for line in lines:
                if '"key":' in line and '"value":' in line:
                    try:
                        # Extract key and value from JSON-like text
                        key_match = line.split('"key":')[1].split(',')[0].strip()
                        key = int(key_match)

                        # Find all values
                        value_parts = line.split('"value":')[1:]
                        total = 0
                        for part in value_parts:
                            if part.strip().isdigit():
                                total += int(part.strip())
                        values[key] = total
                    except:
                        continue

        return values

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
        print(f"Starting Optimized RSS Reader on interface {self.interface}")
        print(f"Max buckets: {self.max_buckets}")
        print(f"Stats interval: {self.stats_interval} seconds")
        print("Press Ctrl+C to stop...")

        # Find map ID once
        map_id = self.find_map_id('bucket_counters')
        if not map_id:
            print("Warning: Could not find bucket_counters map")
            print("Make sure the XDP program is loaded first:")
            print(f"  sudo-rs ip link set dev {self.interface} xdpgeneric obj xdp_rss_simple.o sec xdp")
            return

        print(f"✓ Found bucket_counters map (ID: {map_id})")

        last_counters = {}

        while self.running:
            try:
                start_time = time.time()

                # Read counters using optimized method
                current_counters = self.read_map_values_optimized()

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

                # Sleep for remaining time
                elapsed = time.time() - start_time
                sleep_time = max(0, self.stats_interval - elapsed)
                time.sleep(sleep_time)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(1)

        print("\nReader stopped")

def main():
    parser = argparse.ArgumentParser(description='Optimized RSS Reader for XDP program')
    parser.add_argument('-i', '--interface', default='lo',
                       help='Network interface name (default: lo)')
    parser.add_argument('-b', '--buckets', type=int, default=8,
                       help='Number of buckets (default: 8)')
    parser.add_argument('-s', '--stats-interval', type=int, default=3,
                       help='Statistics interval in seconds (default: 3)')

    args = parser.parse_args()

    reader = OptimizedRSSReader(
        interface=args.interface,
        max_buckets=args.buckets,
        stats_interval=args.stats_interval
    )

    reader.run()

if __name__ == '__main__':
    main()