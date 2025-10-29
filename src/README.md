# XDP Software RSS with Argus Integration

A complete implementation of software-based RSS (Receive Side Scaling) using XDP for network flow monitoring with Argus integration. This system enables flow steering and load balancing when hardware RSS is not available.

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Network       │    │   XDP Program    │    │   User Space    │
│   Interface     │───▶│   (soft_rss)     │───▶│   Readers       │
│   (wlo1)        │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌──────────────┐         ┌──────────────┐
                       │   BPF Maps   │         │   Flow       │
                       │ - Counters   │         │   Statistics │
                       │ - Events     │         │   Bucketing  │
                       └──────────────┘         └──────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │   Argus         │
                                               │   Instances     │
                                               │   (N buckets)   │
                                               └─────────────────┘
```

## 📁 Files

- `xdp_soft_rss.c` - XDP program for software RSS implementation
- `soft_rss_reader.py` - Python script to read flow events and display statistics
- `argus_integration.py` - Python script to manage multiple Argus instances based on flow buckets
- `test_soft_rss.sh` - Test script for the complete system
- `README.md` - This documentation

## 🚀 Quick Start

### Prerequisites

```bash
# Install required packages
sudo apt-get update
sudo apt-get install -y \
    clang \
    linux-headers-$(uname -r) \
    python3-bpfcc \
    bpfcc-tools \
    iproute2 \
    argus-client

# Install Python dependencies
sudo pip3 install bcc
```

### 1. Compile the XDP Program

```bash
cd /path/to/ids-tesis/src
clang -O2 -target bpf -c xdp_soft_rss.c -o xdp_soft_rss.o
```

### 2. Load the XDP Program

**If you encounter BTF errors (common on zen kernels):**

```bash
# Quick fix for BTF errors
sudo ./fix_btf_error.sh

# Or use the comprehensive test
sudo ./test_xdp_loading.sh
```

**Standard loading (if no BTF errors):**

```bash
# Load in generic mode (works on most interfaces)
sudo ip link set dev wlo1 xdp obj xdp_soft_rss.o sec xdp generic

# Verify it's loaded
sudo bpftool prog show
```

### 3. Run the Flow Reader

```bash
# Basic flow monitoring
sudo python3 soft_rss_reader.py -i wlo1

# With custom settings
sudo python3 soft_rss_reader.py -i wlo1 -s 5 -o flow_stats.json
```

### 4. Run with Argus Integration

```bash
# Start multiple Argus instances based on flow buckets
sudo python3 argus_integration.py -i wlo1 -b 8 -s 30
```

## 🔧 Configuration

### XDP Program Settings

Edit `xdp_soft_rss.c` to modify:

- `MAX_BUCKETS` - Number of flow buckets (default: 8)
- `FLOW_THRESHOLD` - Packets per flow before triggering events (default: 100)
- Hash function - Modify `flow_hash()` for different distribution

### Reader Settings

```bash
python3 soft_rss_reader.py --help
# Options:
#   -i, --interface        Network interface (default: wlo1)
#   -b, --buckets         Number of buckets (default: 8)
#   -s, --stats-interval  Statistics interval in seconds (default: 10)
#   -o, --output          Save state to file
```

### Argus Integration Settings

```bash
python3 argus_integration.py --help
# Options:
#   -i, --interface        Network interface (default: wlo1)
#   -b, --buckets         Number of Argus instances (default: 8)
#   -o, --output-dir      Output directory for Argus data
#   -s, --stats-interval  Statistics interval in seconds (default: 30)
#   -c, --config-file     Save configuration to file
```

## 📊 Features

### XDP Soft RSS Program
- **5-tuple hashing**: Source IP, destination IP, source port, destination port, protocol
- **Flow distribution**: Consistent hashing to N buckets
- **Elephant flow detection**: Emits events for high-volume flows
- **Per-bucket counters**: Track load distribution
- **BPF maps**: LRU hash for flow tracking, per-CPU counters for buckets

### Python Reader
- **Real-time monitoring**: Live flow events and statistics
- **Bucket statistics**: Packets and flows per bucket
- **Elephant flow tracking**: Identify and monitor high-volume flows
- **State persistence**: Save and restore flow state
- **Performance metrics**: Events per second, flow distribution

### Argus Integration
- **Dynamic Argus management**: Start/stop Argus instances per bucket
- **Flow-based filtering**: Each Argus instance handles specific flows
- **Automatic restart**: Restart Argus when new flows are added
- **Configuration management**: Save flow-to-bucket mappings
- **Process monitoring**: Track Argus instance health

## 🧪 Testing

Run the comprehensive test suite:

```bash
./test_soft_rss.sh
```

This will:
1. Verify XDP object compilation
2. Check system dependencies
3. Test Python script syntax
4. Optionally run a 30-second live test

## 📈 Performance

### Expected Performance (XDP Generic Mode)
- **Throughput**: 1-3 Mpps (depending on CPU and interface)
- **CPU Usage**: ~10-20% per core at 1 Mpps
- **Memory**: ~50MB for BPF maps and user-space tracking
- **Latency**: < 100μs additional processing overhead

### Scaling Characteristics
- **Linear scaling**: Performance scales with CPU cores
- **Bucket distribution**: Even distribution with consistent hashing
- **Memory usage**: Grows with number of unique flows (LRU eviction)

## 🔍 Monitoring and Debugging

### Check XDP Program Status
```bash
# Show loaded XDP programs
sudo bpftool prog show

# Show BPF maps
sudo bpftool map show

# Check interface XDP status
ip link show dev wlo1
```

### Monitor System Performance
```bash
# CPU usage
htop

# Network statistics
sar -n DEV 1

# BPF program statistics
sudo bpftool prog show xdp
```

### Debug Flow Events
```bash
# Run reader with verbose output
sudo python3 soft_rss_reader.py -i wlo1 -s 1

# Check Argus instance status
ps aux | grep argus
```

## 🛠️ Advanced Usage

### Custom Hash Functions

Modify the `flow_hash()` function in `xdp_soft_rss.c`:

```c
static __always_inline __u32 flow_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 proto) {
    // Custom hash implementation
    __u32 hash = (saddr * 31) ^ (daddr * 37) ^ (sport * 41) ^ (dport * 43) ^ (proto * 47);
    return hash;
}
```

### Integration with External Systems

The flow events can be forwarded to external systems:

```python
# In soft_rss_reader.py, modify handle_flow_event():
def handle_flow_event(self, cpu, data, size):
    event = self.bpf["events"].event(data)

    # Send to external system
    flow_data = {
        'bucket': event.bucket,
        'src_ip': self.inet_ntoa(event.saddr),
        'dst_ip': self.inet_ntoa(event.daddr),
        'timestamp': time.time()
    }

    # Send to Kafka, Redis, etc.
    # kafka_producer.send('flow_events', flow_data)
```

### Custom Argus Filters

The Argus integration can be extended with custom filters:

```python
# In argus_integration.py, modify ArgusInstance.add_flow_filter():
def add_flow_filter(self, src_ip, dst_ip, src_port, dst_port, proto):
    # Custom filter logic
    if self.is_internal_network(src_ip):
        filter_expr = f"host {src_ip} and not port 22"  # Exclude SSH
    else:
        filter_expr = f"host {src_ip}"

    self.flow_filters.append(filter_expr)
```

## 🚨 Troubleshooting

### Common Issues

1. **Permission denied errors**
   ```bash
   # Ensure running with sudo for XDP operations
   sudo python3 soft_rss_reader.py -i wlo1
   ```

2. **BTF Error: "BTF is required, but is missing or corrupted"**

   This is common on zen kernels and some custom kernel configurations.

   **Quick Fix:**
   ```bash
   # Automatic BTF fix
   sudo ./fix_btf_error.sh
   ```

   **Manual Fix:**
   ```bash
   # Try different compilation methods
   clang -g -O2 -target bpf -c xdp_soft_rss.c -o xdp_soft_rss_debug.o
   sudo ip link set dev wlo1 xdp obj xdp_soft_rss_debug.o sec xdp generic

   # Or use simplified program
   clang -O2 -target bpf -c xdp_simple_rss.c -o xdp_simple_rss.o
   sudo ip link set dev wlo1 xdp obj xdp_simple_rss.o sec xdp generic
   ```

3. **XDP program fails to load**
   ```bash
   # Check if interface supports XDP
   ethtool -k wlo1 | grep xdp

   # Try generic mode (always supported)
   sudo ip link set dev wlo1 xdp obj xdp_soft_rss.o sec xdp generic

   # Use the test script to find working compilation
   sudo ./test_xdp_loading.sh
   ```

4. **BCC module not found**
   ```bash
   # Install BCC
   sudo apt-get install python3-bpfcc bpfcc-tools
   ```

5. **Argus fails to start**
   ```bash
   # Check if argus is installed
   which argus

   # Install argus
   sudo apt-get install argus-client
   ```

### Performance Issues

1. **High CPU usage**
   - Reduce `FLOW_THRESHOLD` to emit fewer events
   - Increase bucket count for better distribution
   - Use `perf` to identify bottlenecks

2. **Memory usage growing**
   - Check BPF map sizes
   - Verify LRU eviction is working
   - Reduce flow tracking window

3. **Packet drops**
   - Check XDP program return values
   - Monitor interface statistics
   - Consider using `XDP_DROP` for unwanted traffic

## 📚 References

- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [BCC Documentation](https://github.com/iovisor/bcc)
- [Argus Documentation](http://qosient.com/argus/)
- [eBPF Reference Guide](https://ebpf.io/what-is-ebpf/)

## 📄 License

This project follows the same license as the research repository. The XDP program uses GPL license as required for kernel modules.

## 🤝 Contributing

This is part of a research project. For contributions or issues, please follow the repository's contribution guidelines.

---

**Note**: This system is designed for research and educational purposes. For production use, consider additional security hardening, error handling, and performance optimization.