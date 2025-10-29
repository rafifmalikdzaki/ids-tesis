#!/bin/bash
# Test script to find which XDP compilation works on the zen kernel

set -e

INTERFACE="wlo1"
XDP_OBJECTS=(
    "xdp_soft_rss_no_btf1.o"  # With -g flag
    "xdp_soft_rss_no_btf2.o"  # With -Wno-btf (may have warning)
    "xdp_soft_rss_no_btf3.o"  # Simplified flags
    "xdp_simple_rss.o"        # Simplified program
)

echo "=== XDP Loading Test Script ==="
echo "Interface: $INTERFACE"
echo "Testing different XDP object files..."
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "⚠️  This script requires root privileges to load XDP programs"
    echo "   Run with: sudo $0"
    exit 1
fi

# Function to test XDP loading
test_xdp_loading() {
    local obj_file=$1
    local description=$2

    echo "Testing: $description"
    echo "  File: $obj_file"

    if [[ ! -f "$obj_file" ]]; then
        echo "  ❌ File not found"
        return 1
    fi

    # Check file size
    local size=$(stat -c%s "$obj_file" 2>/dev/null || echo "unknown")
    echo "  Size: $size bytes"

    # Remove any existing XDP program
    ip link set dev "$INTERFACE" xdp off 2>/dev/null || true

    # Try to load XDP program
    if ip link set dev "$INTERFACE" xdp obj "$obj_file" sec xdp generic 2>/dev/null; then
        echo "  ✅ Successfully loaded!"

        # Show program info
        echo "  Program info:"
        bpftool prog show | grep -A5 -B5 "$INTERFACE" || echo "    (No program details found)"

        # Clean up
        ip link set dev "$INTERFACE" xdp off 2>/dev/null || true

        return 0
    else
        echo "  ❌ Failed to load"
        return 1
    fi
}

# Test each XDP object
echo "Testing XDP object files..."
echo

success_count=0
total_tests=${#XDP_OBJECTS[@]}

for i in "${!XDP_OBJECTS[@]}"; do
    obj_file="${XDP_OBJECTS[$i]}"

    case $obj_file in
        "xdp_soft_rss_no_btf1.o")
            description="Original program with -g debug flag"
            ;;
        "xdp_soft_rss_no_btf2.o")
            description="Original program with -Wno-btf flag (warning expected)"
            ;;
        "xdp_soft_rss_no_btf3.o")
            description="Original program with simplified flags"
            ;;
        "xdp_simple_rss.o")
            description="Simplified program (no complex maps)"
            ;;
        *)
            description="Unknown compilation method"
            ;;
    esac

    echo "=== Test $((i+1))/$total_tests ==="
    if test_xdp_loading "$obj_file" "$description"; then
        success_count=$((success_count + 1))
        echo "  🎯 This version works!"
        echo
    else
        echo "  ❌ This version failed"
        echo
    fi
done

echo "=== Test Results ==="
echo "Successful: $success_count/$total_tests"
echo "Failed: $((total_tests - success_count))/$total_tests"

if [[ $success_count -gt 0 ]]; then
    echo
    echo "✅ At least one XDP version works!"
    echo "You can now use the working version for your Soft RSS system."
    echo
    echo "To load the working XDP program:"
    echo "  sudo ip link set dev $INTERFACE xdp obj <working_file.o> sec xdp generic"
else
    echo
    echo "❌ No XDP versions worked on this kernel."
    echo "This might indicate a deeper compatibility issue with the zen kernel."
    echo
    echo "Alternative solutions:"
    echo "1. Try a different kernel version"
    echo "2. Use tc (traffic control) instead of XDP"
    echo "3. Use a userspace packet capture approach"
fi

echo
echo "=== BTF Diagnostics ==="
echo "BTF file info:"
if [[ -f /sys/kernel/btf/vmlinux ]]; then
    echo "  BTF file exists: $(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo "unknown size") bytes"
else
    echo "  BTF file missing"
fi

echo "Kernel BTF support:"
if grep -q CONFIG_DEBUG_INFO_BTF=y /boot/config-$(uname -r) 2>/dev/null; then
    echo "  BTF enabled in kernel config"
else
    echo "  BTF not enabled in kernel config (or config not found)"
fi