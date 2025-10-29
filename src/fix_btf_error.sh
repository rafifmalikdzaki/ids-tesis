#!/bin/bash
# Quick fix for BTF error on zen kernel

set -e

echo "=== XDP BTF Error Fix Script ==="
echo "Kernel: $(uname -r)"
echo "Interface: wlo1"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script requires root privileges to load XDP programs"
    echo "Run with: sudo $0"
    exit 1
fi

# Remove any existing XDP program
echo "Cleaning up existing XDP programs..."
ip link set dev wlo1 xdp off 2>/dev/null || true

echo "Trying different XDP compilation methods..."
echo

# Method 1: Try the version with debug info (-g flag)
echo "1. Testing XDP program with debug info (-g flag)..."
if clang -g -O2 -target bpf -c xdp_soft_rss.c -o xdp_soft_rss_debug.o 2>/dev/null; then
    echo "   ✓ Compilation successful"
    if ip link set dev wlo1 xdp obj xdp_soft_rss_debug.o sec xdp generic 2>/dev/null; then
        echo "   ✅ SUCCESS! XDP program loaded with debug info"
        echo "   File: xdp_soft_rss_debug.o"
        echo
        echo "Your XDP Software RSS system is now ready!"
        echo "Start the flow reader with:"
        echo "  python3 soft_rss_reader.py -i wlo1"
        exit 0
    else
        echo "   ❌ Failed to load"
    fi
else
    echo "   ❌ Compilation failed"
fi

# Method 2: Try simplified flags
echo
echo "2. Testing XDP program with simplified flags..."
if clang -target bpf -O2 -c xdp_soft_rss.c -o xdp_soft_rss_simple.o 2>/dev/null; then
    echo "   ✓ Compilation successful"
    if ip link set dev wlo1 xdp obj xdp_soft_rss_simple.o sec xdp generic 2>/dev/null; then
        echo "   ✅ SUCCESS! XDP program loaded with simplified flags"
        echo "   File: xdp_soft_rss_simple.o"
        echo
        echo "Your XDP Software RSS system is now ready!"
        echo "Start the flow reader with:"
        echo "  python3 soft_rss_reader.py -i wlo1"
        exit 0
    else
        echo "   ❌ Failed to load"
    fi
else
    echo "   ❌ Compilation failed"
fi

# Method 3: Try simplified program
echo
echo "3. Testing simplified XDP program..."
if clang -O2 -target bpf -c xdp_simple_rss.c -o xdp_simple_rss.o 2>/dev/null; then
    echo "   ✓ Compilation successful"
    if ip link set dev wlo1 xdp obj xdp_simple_rss.o sec xdp generic 2>/dev/null; then
        echo "   ✅ SUCCESS! Simplified XDP program loaded"
        echo "   File: xdp_simple_rss.o"
        echo
        echo "Your XDP Software RSS system is now ready!"
        echo "Start the flow reader with:"
        echo "  python3 soft_rss_reader.py -i wlo1"
        exit 0
    else
        echo "   ❌ Failed to load"
    fi
else
    echo "   ❌ Compilation failed"
fi

# All methods failed
echo
echo "❌ All methods failed. This suggests a deeper BTF/kernel compatibility issue."
echo
echo "Diagnostic information:"
echo "BTF file: $(ls -la /sys/kernel/btf/vmlinux 2>/dev/null || echo 'Not found')"
echo "Kernel config: $(grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r) 2>/dev/null || echo 'Not found')"
echo
echo "Alternative solutions:"
echo "1. Install kernel debug symbols:"
echo "   sudo apt-get install linux-image-$(uname -r)-dbg"
echo
echo "2. Try generating BTF from vmlinux:"
echo "   sudo bpftool btf dump file /boot/vmlinux-$(uname -r) format raw > /tmp/vmlinux.btf"
echo "   sudo mount -t bpf bpf /sys/fs/bpf"
echo "   sudo mkdir -p /sys/kernel/btf"
echo "   sudo cp /tmp/vmlinux.btf /sys/kernel/btf/vmlinux"
echo
echo "3. Use userspace packet capture instead of XDP"
echo
echo "4. Try a different kernel version (non-zen kernel if possible)"