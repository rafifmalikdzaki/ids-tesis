#!/usr/bin/env python3
"""
Argus Integration for Soft RSS System
Manages multiple Argus instances based on flow bucket distribution
"""

import os
import sys
import time
import json
import socket
import struct
import subprocess
import signal
import argparse
from collections import defaultdict, deque
from datetime import datetime
from threading import Thread, Lock
import uuid

try:
    from bcc import BPF
except ImportError:
    print("Error: BCC not found. Install with: sudo apt-get install python3-bpfcc")
    sys.exit(1)


class ArgusInstance:
    """Manages a single Argus process for a specific bucket"""

    def __init__(self, bucket_id, interface, output_dir="/tmp/argus_data"):
        self.bucket_id = bucket_id
        self.interface = interface
        self.output_dir = output_dir
        self.process = None
        self.output_file = f"{output_dir}/argus_bucket_{bucket_id}.argus"
        self.pid_file = f"{output_dir}/argus_bucket_{bucket_id}.pid"
        self.running = False
        self.flow_filters = []

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def add_flow_filter(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Add a flow filter for this bucket"""
        filter_expr = f"host {src_ip} and host {dst_ip}"
        if src_port and dst_port:
            filter_expr += f" and port {src_port} and port {dst_port}"
        if proto and proto != 'ANY':
            filter_expr += f" and {proto.lower()}"

        self.flow_filters.append(filter_expr)

    def get_filter_expression(self):
        """Generate combined filter expression for all flows in this bucket"""
        if not self.flow_filters:
            return None

        if len(self.flow_filters) == 1:
            return self.flow_filters[0]

        # Combine multiple filters with OR
        return " or ".join(f"({f})" for f in self.flow_filters)

    def start(self, port_offset=5000):
        """Start Argus instance for this bucket"""
        if self.running:
            return True

        try:
            # Kill any existing Argus process for this bucket
            self.stop()

            # Generate unique port for this instance
            argus_port = port_offset + self.bucket_id

            # Build Argus command
            cmd = [
                "sudo", "argus",
                "-i", self.interface,
                "-P", str(argus_port),
                "-w", self.output_file,
                "-d",  # Run as daemon
            ]

            # Add flow filter if we have one
            filter_expr = self.get_filter_expression()
            if filter_expr:
                cmd.extend(["-f", filter_expr])
                print(f"Starting Argus bucket {self.bucket_id} with filter: {filter_expr}")
            else:
                print(f"Starting Argus bucket {self.bucket_id} without filter")

            # Start Argus process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait a bit to check if it started successfully
            time.sleep(1)

            if self.process.poll() is None:
                self.running = True
                # Write PID file
                with open(self.pid_file, 'w') as f:
                    f.write(str(self.process.pid))
                print(f"✓ Argus bucket {self.bucket_id} started (PID: {self.process.pid}, Port: {argus_port})")
                return True
            else:
                stdout, stderr = self.process.communicate()
                print(f"✗ Failed to start Argus bucket {self.bucket_id}: {stderr}")
                return False

        except Exception as e:
            print(f"Error starting Argus bucket {self.bucket_id}: {e}")
            return False

    def stop(self):
        """Stop Argus instance"""
        if not self.running:
            return

        try:
            # Try to kill using PID file first
            if os.path.exists(self.pid_file):
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)

            # Kill process if we have it
            if self.process:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()

            # Clean up files
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)

            self.running = False
            print(f"✓ Argus bucket {self.bucket_id} stopped")

        except Exception as e:
            print(f"Error stopping Argus bucket {self.bucket_id}: {e}")

    def is_running(self):
        """Check if Argus process is still running"""
        if not self.process:
            return False
        return self.process.poll() is None


class ArgusRSSManager:
    """Manages multiple Argus instances based on RSS buckets"""

    def __init__(self, interface="wlo1", num_buckets=8, output_dir="/tmp/argus_data"):
        self.interface = interface
        self.num_buckets = num_buckets
        self.output_dir = output_dir

        # Argus instances
        self.argus_instances = {
            bucket_id: ArgusInstance(bucket_id, interface, output_dir)
            for bucket_id in range(num_buckets)
        }

        # Flow tracking
        self.bucket_flows = defaultdict(set)
        self.flow_buckets = {}  # flow_key -> bucket_id
        self.lock = Lock()

        # Statistics
        self.stats = {
            'total_flows': 0,
            'bucket_counts': defaultdict(int),
            'argus_restarts': 0,
            'start_time': time.time()
        }

        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down Argus instances...")
        self.shutdown()
        sys.exit(0)

    def inet_ntoa(self, addr):
        """Convert integer IP to dotted notation"""
        try:
            return socket.inet_ntoa(struct.pack("<I", addr))
        except:
            return f"0.0.0.{addr}"

    def proto_to_string(self, proto):
        """Convert protocol number to string"""
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return proto_map.get(proto, 'ANY')

    def handle_flow_event(self, cpu, data, size):
        """Handle flow events and distribute to appropriate Argus bucket"""
        event = self.bpf["events"].event(data)

        src_ip = self.inet_ntoa(event.saddr)
        dst_ip = self.inet_ntoa(event.daddr)
        src_port = socket.ntohs(event.sport) if event.sport else 0
        dst_port = socket.ntohs(event.dport) if event.dport else 0
        proto = self.proto_to_string(event.proto)

        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        bucket_id = event.bucket

        with self.lock:
            # Track flow assignment
            if flow_key not in self.flow_buckets:
                self.flow_buckets[flow_key] = bucket_id
                self.bucket_flows[bucket_id].add(flow_key)
                self.stats['total_flows'] += 1
                self.stats['bucket_counts'][bucket_id] += 1

                # Add flow filter to Argus instance
                argus = self.argus_instances[bucket_id]
                argus.add_flow_filter(src_ip, dst_ip, src_port, dst_port, proto)

                # Restart Argus if it's not running to pick up new filter
                if not argus.is_running():
                    print(f"Restarting Argus bucket {bucket_id} for new flow filters")
                    argus.start()
                    self.stats['argus_restarts'] += 1

            # Print assignment
            if event.packet_count % 500 == 0:  # Print every 500 packets
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] Flow {flow_key} → Bucket {bucket_id} "
                      f"({event.packet_count} packets)")

    def start_all_argus(self):
        """Start all Argus instances"""
        print(f"Starting {self.num_buckets} Argus instances...")

        for bucket_id, argus in self.argus_instances.items():
            if argus.start():
                time.sleep(0.1)  # Small delay between starts
            else:
                print(f"Failed to start Argus bucket {bucket_id}")

    def shutdown(self):
        """Shutdown all Argus instances"""
        print("Shutting down all Argus instances...")
        for argus in self.argus_instances.values():
            argus.stop()

    def print_statistics(self):
        """Print current statistics"""
        print(f"\n{'='*80}")
        print(f"ARGUS RSS MANAGER STATISTICS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")

        runtime = time.time() - self.stats['start_time']
        print(f"Runtime: {runtime:.1f} seconds")
        print(f"Total flows tracked: {self.stats['total_flows']}")
        print(f"Argus restarts: {self.stats['argus_restarts']}")
        print()

        print("Bucket Distribution:")
        for bucket_id in range(self.num_buckets):
            count = self.stats['bucket_counts'][bucket_id]
            argus = self.argus_instances[bucket_id]
            status = "RUNNING" if argus.is_running() else "STOPPED"
            filters = len(argus.flow_filters)
            print(f"  Bucket {bucket_id:2d}: {count:4d} flows, {filters:3d} filters, {status}")

        print(f"{'='*80}")

    def save_configuration(self, filename):
        """Save current flow-to-bucket mapping"""
        config = {
            'timestamp': time.time(),
            'interface': self.interface,
            'num_buckets': self.num_buckets,
            'flow_buckets': self.flow_buckets,
            'bucket_flows': {k: list(v) for k, v in self.bucket_flows.items()},
            'statistics': self.stats
        }

        with open(filename, 'w') as f:
            json.dump(config, f, indent=2, default=str)
        print(f"Configuration saved to {filename}")

    def run(self, stats_interval=30, config_file=None):
        """Main execution loop"""
        print(f"Starting Argus RSS Manager on interface {self.interface}")
        print(f"Managing {self.num_buckets} Argus instances")
        print(f"Output directory: {self.output_dir}")

        # Start all Argus instances
        self.start_all_argus()

        # Load BPF program
        try:
            bpf_text = open('xdp_soft_rss.c').read()
            self.bpf = BPF(text=bpf_text)
            fn = self.bpf.load_func("xdp_soft_rss", BPF.XDP)
            self.bpf.attach_xdp(self.interface, fn, 0)

            print(f"✓ XDP program loaded on {self.interface}")

            # Setup perf buffer
            self.bpf["events"].open_perf_buffer(self.handle_flow_event, page_cnt=64)

            running = True
            last_stats_time = time.time()
            last_config_time = time.time()

            while running:
                try:
                    self.bpf.perf_buffer_poll(timeout=1000)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error polling perf buffer: {e}")
                    time.sleep(0.1)

                current_time = time.time()

                # Print statistics
                if current_time - last_stats_time >= stats_interval:
                    self.print_statistics()
                    last_stats_time = current_time

                # Save configuration
                if config_file and current_time - last_config_time >= 300:  # Every 5 minutes
                    self.save_configuration(config_file)
                    last_config_time = current_time

        except Exception as e:
            print(f"Error: {e}")
            return 1

        finally:
            self.shutdown()

        return 0


def main():
    parser = argparse.ArgumentParser(description='Argus RSS Manager - Flow-based Argus instance management')
    parser.add_argument('-i', '--interface', default='wlo1',
                       help='Network interface to monitor (default: wlo1)')
    parser.add_argument('-b', '--buckets', type=int, default=8,
                       help='Number of buckets/Argus instances (default: 8)')
    parser.add_argument('-o', '--output-dir', default='/tmp/argus_data',
                       help='Output directory for Argus data (default: /tmp/argus_data)')
    parser.add_argument('-s', '--stats-interval', type=int, default=30,
                       help='Statistics display interval in seconds (default: 30)')
    parser.add_argument('-c', '--config-file', help='Save configuration to file')

    args = parser.parse_args()

    # Check if running as root (required for Argus and XDP)
    if os.geteuid() != 0:
        print("Error: This script requires root privileges for Argus and XDP operations")
        print("Run with: sudo python3 argus_integration.py")
        return 1

    # Check if Argus is available
    try:
        subprocess.run(['which', 'argus'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Error: Argus not found. Please install Argus")
        print("Install with: sudo apt-get install argus-client")
        return 1

    manager = ArgusRSSManager(args.interface, args.buckets, args.output_dir)
    return manager.run(args.stats_interval, args.config_file)


if __name__ == '__main__':
    sys.exit(main())