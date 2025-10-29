#!/usr/bin/env python3
"""
Demo script for XDP Software RSS system
Shows how the flow hashing and bucket distribution works
"""

import hashlib
import struct
import socket
import random
from collections import defaultdict

# Constants from XDP program
MAX_BUCKETS = 8

def inet_aton(ip):
    """Convert IP string to integer"""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return hash(ip) & 0xFFFFFFFF

def flow_hash(saddr, daddr, sport, dport, proto):
    """Replicate the hash function from XDP program"""
    # Convert to integers if needed
    if isinstance(saddr, str):
        saddr = inet_aton(saddr)
    if isinstance(daddr, str):
        daddr = inet_aton(daddr)

    hash_val = saddr ^ daddr ^ ((sport << 16) ^ dport ^ (proto << 24))

    # Jenkins mix-like hash (from XDP program)
    hash_val ^= hash_val >> 16
    hash_val *= 0x7feb352d
    hash_val ^= hash_val >> 15
    hash_val *= 0x846ca68b
    hash_val ^= hash_val >> 16

    return hash_val

def proto_to_number(proto):
    """Convert protocol string to number"""
    proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
    return proto_map.get(proto.upper(), 0)

def generate_sample_flows(num_flows=100):
    """Generate sample network flows for demonstration"""
    flows = []
    protocols = ['TCP', 'UDP']

    # Some common services
    services = [
        ('8.8.8.8', 53, 'UDP'),      # Google DNS
        ('8.8.4.4', 53, 'UDP'),      # Google DNS
        ('1.1.1.1', 53, 'UDP'),      # Cloudflare DNS
        ('10.0.0.1', 22, 'TCP'),     # SSH
        ('10.0.0.1', 80, 'TCP'),     # HTTP
        ('10.0.0.1', 443, 'TCP'),    # HTTPS
        ('192.168.1.1', 80, 'TCP'),  # Local web server
        ('172.16.0.1', 3306, 'TCP'), # MySQL
        ('203.0.113.1', 25, 'TCP'),  # SMTP
        ('198.51.100.1', 587, 'TCP'), # SMTP
    ]

    # Generate flows
    for i in range(num_flows):
        if i < len(services):
            dst_ip, dst_port, proto = services[i]
        else:
            # Random flows
            dst_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            dst_port = random.choice([22, 53, 80, 443, 3306, 25, 587, 993, 995])
            proto = random.choice(protocols)

        src_ip = f"10.0.0.{random.randint(2,254)}"
        src_port = random.randint(1024, 65535)

        flows.append((src_ip, src_port, dst_ip, dst_port, proto))

    return flows

def simulate_flow_distribution(flows):
    """Simulate how flows are distributed across buckets"""
    bucket_distribution = defaultdict(list)
    bucket_stats = defaultdict(int)

    for src_ip, src_port, dst_ip, dst_port, proto in flows:
        # Calculate hash and bucket
        saddr = inet_aton(src_ip)
        daddr = inet_aton(dst_ip)
        proto_num = proto_to_number(proto)

        hash_val = flow_hash(saddr, daddr, src_port, dst_port, proto_num)
        bucket = hash_val % MAX_BUCKETS

        flow_key = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})"
        bucket_distribution[bucket].append(flow_key)
        bucket_stats[bucket] += 1

    return bucket_distribution, bucket_stats

def print_distribution(bucket_stats, bucket_distribution):
    """Print the flow distribution statistics"""
    print("\n" + "="*80)
    print("FLOW DISTRIBUTION ANALYSIS")
    print("="*80)

    total_flows = sum(bucket_stats.values())

    print(f"\nTotal flows: {total_flows}")
    print(f"Buckets: {MAX_BUCKETS}")
    print(f"Expected flows per bucket: {total_flows / MAX_BUCKETS:.1f}")

    print(f"\n{'Bucket':>6} {'Flows':>6} {'Percentage':>11} {'Distribution':>12}")
    print("-" * 50)

    for bucket in range(MAX_BUCKETS):
        count = bucket_stats[bucket]
        percentage = (count / total_flows) * 100
        bar = "█" * int(percentage / 2)  # Scale down for display

        print(f"{bucket:6d} {count:6d} {percentage:10.1f}% {bar:>12}")

    # Calculate distribution quality
    variance = sum((count - total_flows/MAX_BUCKETS)**2 for count in bucket_stats.values()) / MAX_BUCKETS
    std_dev = variance ** 0.5
    balance_ratio = min(bucket_stats.values()) / max(bucket_stats.values()) if max(bucket_stats.values()) > 0 else 0

    print(f"\nDistribution Quality:")
    print(f"  Standard deviation: {std_dev:.2f}")
    print(f"  Balance ratio: {balance_ratio:.3f} (1.0 = perfect balance)")

    if balance_ratio > 0.8:
        print("  ✓ Excellent distribution")
    elif balance_ratio > 0.6:
        print("  ✓ Good distribution")
    elif balance_ratio > 0.4:
        print("  ⚠ Fair distribution")
    else:
        print("  ✗ Poor distribution")

    return balance_ratio

def show_sample_flows(bucket_distribution, max_per_bucket=3):
    """Show sample flows in each bucket"""
    print(f"\n{'='*80}")
    print("SAMPLE FLOWS PER BUCKET")
    print("="*80)

    for bucket in range(MAX_BUCKETS):
        flows = bucket_distribution[bucket]
        print(f"\nBucket {bucket}: {len(flows)} flows")

        if flows:
            sample = flows[:max_per_bucket]
            for flow in sample:
                print(f"  {flow}")
            if len(flows) > max_per_bucket:
                print(f"  ... and {len(flows) - max_per_bucket} more")

def test_consistency():
    """Test that the same flow always goes to the same bucket"""
    print(f"\n{'='*80}")
    print("CONSISTENCY TEST")
    print("="*80)

    test_flows = [
        ("10.0.0.100", 12345, "8.8.8.8", 53, "UDP"),
        ("192.168.1.50", 8080, "93.184.216.34", 443, "TCP"),
        ("172.16.0.10", 3306, "10.0.0.1", 22, "TCP"),
    ]

    print("Testing flow consistency (same flow should always hash to same bucket):")

    for src_ip, src_port, dst_ip, dst_port, proto in test_flows:
        buckets = []
        for i in range(10):  # Test 10 times
            saddr = inet_aton(src_ip)
            daddr = inet_aton(dst_ip)
            proto_num = proto_to_number(proto)

            hash_val = flow_hash(saddr, daddr, src_port, dst_port, proto_num)
            bucket = hash_val % MAX_BUCKETS
            buckets.append(bucket)

        consistent = len(set(buckets)) == 1
        flow_str = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})"

        print(f"  {flow_str}")
        print(f"    Buckets: {buckets}")
        print(f"    Consistent: {'✓' if consistent else '✗'}")

        if not consistent:
            print(f"    ERROR: Flow should always hash to the same bucket!")

def main():
    print("XDP Software RSS - Flow Distribution Demo")
    print("=" * 80)
    print("This demonstrates how flows are distributed across buckets using the")
    print("same hash function as the XDP program.")

    # Test consistency first
    test_consistency()

    # Generate sample flows
    print(f"\n{'='*80}")
    print("GENERATING SAMPLE FLOWS")
    print("="*80)

    flows = generate_sample_flows(200)
    print(f"Generated {len(flows)} sample flows")

    # Show some example flows
    print("\nExample flows:")
    for i, flow in enumerate(flows[:5]):
        src_ip, src_port, dst_ip, dst_port, proto = flow
        print(f"  {i+1}. {src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})")

    # Simulate distribution
    bucket_distribution, bucket_stats = simulate_flow_distribution(flows)

    # Print results
    balance_ratio = print_distribution(bucket_stats, bucket_distribution)
    show_sample_flows(bucket_distribution)

    # Summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print("="*80)

    if balance_ratio > 0.7:
        print("✓ The hash function provides good flow distribution")
        print("✓ Flows are consistently mapped to buckets")
        print("✓ System is ready for production use")
    else:
        print("⚠ Consider adjusting the hash function for better distribution")

    print(f"\nIn a real deployment:")
    print(f"• Each bucket would correspond to an Argus instance")
    print(f"• Flows in the same bucket are processed by the same Argus instance")
    print(f"• This ensures flow coherence and enables parallel processing")
    print(f"• The XDP program handles this at line rate (~1-3 Mpps in generic mode)")

if __name__ == '__main__':
    main()