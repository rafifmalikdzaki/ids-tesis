#!/usr/bin/env python3
"""
Fast RSS Reader using direct libbpf calls via ctypes (Arch Linux compatible)
"""

import os
import sys
import time
import signal
import argparse
import struct
from collections import defaultdict
from datetime import datetime
from ctypes import *

# Load libbpf
try:
    libbpf = CDLL("libbpf.so.1")
except OSError:
    try:
        libbpf = CDLL("libbpf.so")
    except OSError:
        print("Error: libbpf not found. Install with: sudo pacman -S libbpf")
        sys.exit(1)

# Define constants and structures
BPF_MAP_TYPE_PERCPU_ARRAY = 7

class bpf_map_info(Structure):
    _fields_ = [
        ("type", c_uint32),
        ("id", c_uint32),
        ("key_size", c_uint32),
        ("value_size", c_uint32),
        ("max_entries", c_uint32),
        ("map_flags", c_uint32),
        ("name", c_char * 256),
        ("ifindex", c_uint32),
        ("btf_vmlinux_value_type_id", c_uint32),
        ("netns_dev", c_uint64),
        ("netns_inode", c_uint64),
        ("btf_id", c_uint32),
        ("btf_key_type_id", c_uint32),
        ("btf_value_type_id", c_uint32),
    ]

class bpf_prog_info(Structure):
    _fields_ = [
        ("type", c_uint32),
        ("id", c_uint32),
        ("tag", c_uint8 * 8),
        ("jited_prog_len", c_uint32),
        ("xlated_prog_len", c_uint32),
        ("jited_ksyms", c_uint64),
        ("btf_id", c_uint32),
        ("bytes_jited", c_uint64),
        ("bytes_xlated", c_uint64),
        ("jited_line_info", c_uint64),
        ("line_info", c_uint64),
        ("jited_func_lens", c_uint64),
        ("func_info", c_uint64),
        ("func_info_rec_size", c_uint32),
        ("btf_func_info", c_uint64),
        ("netns_dev", c_uint64),
        ("netns_inode", c_uint64),
        ("nr_jited_ksyms", c_uint32),
        ("nr_jited_func_lens", c_uint32),
        ("nr_func_info", c_uint32),
        ("nr_line_info", c_uint32),
        ("jited_func_info", c_uint64),
        ("nr_jited_func_info", c_uint32),
        ("nr_prog_tags", c_uint32),
        ("run_time_ns", c_uint64),
        ("run_cnt", c_uint64),
    ]

# Set function prototypes
libbpf.bpf_map_get_next_id.argtypes = [c_uint32, POINTER(c_uint32)]
libbpf.bpf_map_get_next_id.restype = c_int

libbpf.bpf_map_get_fd_by_id.argtypes = [c_uint32]
libbpf.bpf_map_get_fd_by_id.restype = c_int

libbpf.bpf_obj_get_info_by_fd.argtypes = [c_int, POINTER(bpf_map_info)]
libbpf.bpf_obj_get_info_by_fd.restype = c_int

# Don't set argtypes - let ctypes handle it automatically
libbpf.bpf_map_lookup_elem.restype = c_int

libbpf.close.argtypes = [c_int]

class ArchRSSReader:
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
        """Find map ID by name using libbpf"""
        try:
            print(f"Debug: Searching for map '{map_name}'")
            map_id = c_uint32(0)
            map_count = 0
            while True:
                result = libbpf.bpf_map_get_next_id(map_id, byref(map_id))
                if result != 0:
                    print(f"Debug: Found {map_count} maps total")
                    break
                map_count += 1
                print(f"Debug: Checking map ID {map_id.value}")

                # Get map fd
                map_fd = libbpf.bpf_map_get_fd_by_id(map_id)
                print(f"Debug: Map fd for ID {map_id.value}: {map_fd}")
                if map_fd < 0:
                    print(f"Debug: Failed to get fd for map ID {map_id.value}")
                    continue

                try:
                    # Get map info
                    map_info = bpf_map_info()
                    info_len = c_uint(sizeof(bpf_map_info))
                    result = libbpf.bpf_obj_get_info_by_fd(map_fd, byref(map_info))

                    if result == 0:
                        # Check if this is our map
                        current_name = map_info.name.decode('utf-8', errors='ignore').rstrip('\x00')
                        print(f"Debug: Found map '{current_name}' (ID: {map_id.value})")
                        # Use prefix matching since names might be truncated
                        if map_name.startswith(current_name) or current_name.startswith(map_name):
                            self.map_id = map_id.value
                            self.map_fd = map_fd
                            print(f"✓ Found {map_name} map (ID: {map_id.value}) - matched by prefix")
                            return map_id.value

                finally:
                    libbpf.close(map_fd)

        except Exception as e:
            print(f"Error finding map: {e}")

        return None

    def read_map_values(self):
        """Read per-CPU map values using libbpf"""
        if not self.map_fd:
            return {}

        values = {}
        try:
            # Determine number of CPUs
            num_cpus = len(os.sched_getaffinity(0))
            print(f"Debug: Reading map, num_cpus={num_cpus}, map_fd={self.map_fd}")

            for bucket in range(self.max_buckets):
                # Prepare key
                key = struct.pack('I', bucket)

                # Allocate buffer for per-CPU values
                value_size = 8  # 64-bit values
                buffer_size = num_cpus * value_size
                value_buffer = create_string_buffer(buffer_size)

                # Lookup map element - try different calling conventions
                try:
                    # Method 1: Direct call
                    result = libbpf.bpf_map_lookup_elem(self.map_fd, key, value_buffer)
                    print(f"Debug: Bucket {bucket} lookup result (method 1): {result}")
                except:
                    result = -1
                    print(f"Debug: Bucket {bucket} lookup failed (method 1)")
                if result == 0:
                    # Parse per-CPU values
                    total = 0
                    for cpu in range(num_cpus):
                        offset = cpu * value_size
                        if offset + 8 <= buffer_size:
                            value = struct.unpack('<Q', value_buffer[offset:offset+8])[0]
                            total += value
                            print(f"Debug: CPU {cpu} value: {value}")
                    values[bucket] = total
                    print(f"Debug: Bucket {bucket} total: {total}")
                else:
                    values[bucket] = 0
                    print(f"Debug: Bucket {bucket} lookup failed")

        except Exception as e:
            print(f"Error reading map: {e}")
            import traceback
            traceback.print_exc()
            # Fallback: return empty values
            for bucket in range(self.max_buckets):
                values[bucket] = 0

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
        print(f"Starting Arch RSS Reader on interface {self.interface}")
        print(f"Max buckets: {self.max_buckets}")
        print(f"Stats interval: {self.stats_interval} seconds")
        print("Press Ctrl+C to stop...")

        # Find the map
        map_id = self.find_map_id('bucket_counters')
        if not map_id:
            print("Error: Could not find bucket_counters map")
            print("Make sure the XDP program is loaded")
            return

        last_counters = {}

        while self.running:
            try:
                start_time = time.time()

                # Read counters
                current_counters = self.read_map_values()

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

        # Clean up
        if self.map_fd:
            libbpf.close(self.map_fd)

        print("\nReader stopped")

def main():
    parser = argparse.ArgumentParser(description='Arch RSS Reader for XDP program')
    parser.add_argument('-i', '--interface', default='lo',
                       help='Network interface name (default: lo)')
    parser.add_argument('-b', '--buckets', type=int, default=8,
                       help='Number of buckets (default: 8)')
    parser.add_argument('-s', '--stats-interval', type=int, default=3,
                       help='Statistics interval in seconds (default: 3)')

    args = parser.parse_args()

    reader = ArchRSSReader(
        interface=args.interface,
        max_buckets=args.buckets,
        stats_interval=args.stats_interval
    )

    reader.run()

if __name__ == '__main__':
    main()