#!/usr/bin/env python3
"""
Debug reader to check XDP program counters
"""

import subprocess
import struct
import time

def run_bpftool(args):
    """Run bpftool command and return output"""
    try:
        cmd = ['sudo-rs', 'bpftool'] + args
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        print(f"Error running bpftool: {e}")
        return "", str(e)

def find_map_id(map_name):
    """Find map ID by name"""
    stdout, stderr = run_bpftool(['map', 'list'])
    if not stdout:
        return None

    for line in stdout.split('\n'):
        if map_name in line:
            parts = line.split(':')
            if len(parts) > 0:
                try:
                    return int(parts[0])
                except ValueError:
                    continue
    return None

def read_debug_map():
    """Read debug counters"""
    map_id = find_map_id('debug_counters')
    if not map_id:
        print("Could not find debug_counters map")
        return

    stdout, stderr = run_bpftool(['map', 'dump', 'id', str(map_id)])
    if not stdout or stderr:
        print(f"Error reading debug map: {stderr}")
        return

    debug_names = {
        0: "TOTAL_PACKETS",
        1: "IPV4_PACKETS",
        2: "TCP_PACKETS",
        3: "UDP_PACKETS",
        4: "INVALID_PACKETS",
        5: "VALID_TCP_UDP",
        6: "LOOPBACK_PACKETS",
        7: "ETHERNET_PACKETS"
    }

    values = {}
    for line in stdout.split('\n'):
        if '->' in line:
            try:
                parts = line.split('value:')
                if len(parts) == 2:
                    key_part = parts[0].strip()
                    value_part = parts[1].strip()

                    key_bytes = key_part.split(':')[1].strip().split()
                    if len(key_bytes) >= 4:
                        key = int.from_bytes(bytes.fromhex(''.join(key_bytes[:4])), 'little')

                    value_bytes = value_part.split()
                    if len(value_bytes) >= 8:
                        value = int.from_bytes(bytes.fromhex(''.join(value_bytes[:8])), 'little')
                        values[key] = value
            except:
                continue

    print("=== Debug Counters ===")
    for i in range(8):
        count = values.get(i, 0)
        name = debug_names.get(i, f"UNKNOWN_{i}")
        print(f"{name}: {count:,}")

    if values.get(0, 0) > 0:
        print(f"\nPacket Processing Ratio:")
        total = values.get(0, 1)
        ipv4_ratio = (values.get(1, 0) / total) * 100
        tcp_ratio = (values.get(2, 0) / total) * 100
        udp_ratio = (values.get(3, 0) / total) * 100
        valid_ratio = (values.get(5, 0) / total) * 100
        loopback_ratio = (values.get(6, 0) / total) * 100
        ethernet_ratio = (values.get(7, 0) / total) * 100
        print(f"IPv4 packets: {ipv4_ratio:.1f}%")
        print(f"TCP packets:  {tcp_ratio:.1f}%")
        print(f"UDP packets:  {udp_ratio:.1f}%")
        print(f"Valid TCP/UDP: {valid_ratio:.1f}%")
        print(f"Loopback packets: {loopback_ratio:.1f}%")
        print(f"Ethernet packets: {ethernet_ratio:.1f}%")

def read_bucket_map():
    """Read bucket counters"""
    map_id = find_map_id('bucket_counters')
    if not map_id:
        print("Could not find bucket_counters map")
        return

    stdout, stderr = run_bpftool(['map', 'dump', 'id', str(map_id)])
    if not stdout or stderr:
        print(f"Error reading bucket map: {stderr}")
        return

    values = {}
    for line in stdout.split('\n'):
        if '->' in line:
            try:
                parts = line.split('value:')
                if len(parts) == 2:
                    key_part = parts[0].strip()
                    value_part = parts[1].strip()

                    key_bytes = key_part.split(':')[1].strip().split()
                    if len(key_bytes) >= 4:
                        key = int.from_bytes(bytes.fromhex(''.join(key_bytes[:4])), 'little')

                    value_bytes = value_part.split()
                    if len(value_bytes) >= 8:
                        value = int.from_bytes(bytes.fromhex(''.join(value_bytes[:8])), 'little')
                        values[key] = value
            except:
                continue

    print("\n=== Bucket Counters ===")
    total = sum(values.values())
    if total > 0:
        for i in range(8):
            count = values.get(i, 0)
            percentage = (count / total) * 100
            print(f"Bucket {i}: {count:,} ({percentage:.1f}%)")
    else:
        print("No packets processed yet")

def find_xdp_interface():
    """Find which interface has XDP program attached"""
    interfaces = ["lo", "wlo1", "eth0", "enp0s3", "ens33", "enp3s0"]

    for interface in interfaces:
        stdout, stderr = run_bpftool(['net', 'show', 'dev', interface])
        if 'xdp' in stdout.lower():
            return interface
    return None

if __name__ == '__main__':
    print("Debug XDP RSS Reader")
    print("===================")

    # Check if program is loaded
    stdout, stderr = run_bpftool(['prog', 'list'])
    if 'xdp_debug_rss' not in stdout and 'xdp_soft_rss' not in stdout:
        print("No XDP RSS program found!")
        print("Load with: sudo-rs ip link set dev <interface> xdpgeneric obj <program>.o sec xdp")
        exit(1)
    else:
        print("Found XDP RSS program")

        # Find interface with XDP
        interface = find_xdp_interface()
        if interface:
            print(f"XDP program attached to interface: {interface}")
        else:
            print("Could not determine which interface has XDP attached")

    while True:
        try:
            print(f"\n{time.strftime('%H:%M:%S')}")
            read_debug_map()
            read_bucket_map()
            time.sleep(3)
        except KeyboardInterrupt:
            break

    print("\nDebug reader stopped")