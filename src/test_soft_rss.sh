#!/bin/bash
# Test script for Soft RSS system

set -e

INTERFACE="wlo1"
XDP_OBJECT="xdp_soft_rss.o"

echo "=== Soft RSS Test Script ==="
echo "Interface: $INTERFACE"
echo "XDP Object: $XDP_OBJECT"
echo

# Check if running as root for XDP operations
if [[ $EUID -eq 0 ]]; then
    echo "Running as root - will manage XDP program"
    ROOT_MODE=true
else
    echo "Running as user - will only test Python script"
    echo "Note: Run with sudo to load/unload XDP programs"
    ROOT_MODE=false
fi

# Function to cleanup XDP program
cleanup_xdp() {
    if [[ "$ROOT_MODE" == true ]]; then
        echo "Cleaning up XDP program..."
        sudo ip link set dev $INTERFACE xdp off 2>/dev/null || true
        echo "XDP program removed"
    fi
}

# Set cleanup trap
trap cleanup_xdp EXIT

# Step 1: Check if XDP object exists
if [[ ! -f "$XDP_OBJECT" ]]; then
    echo "Error: XDP object $XDP_OBJECT not found"
    echo "Please compile it first: clang -O2 -target bpf -c xdp_soft_rss.c -o $XDP_OBJECT"
    exit 1
fi

echo "✓ XDP object found"

# Step 2: Load XDP program if running as root
if [[ "$ROOT_MODE" == true ]]; then
    echo "Loading XDP program in generic mode..."
    sudo ip link set dev $INTERFACE xdp off
    sudo ip link set dev $INTERFACE xdpgeneric obj $XDP_OBJECT sec xdp

    # Verify it's loaded
    if sudo bpftool prog show | grep -q "xdp"; then
        echo "✓ XDP program loaded successfully"
        sudo bpftool prog show
    else
        echo "✗ Failed to load XDP program"
        exit 1
    fi
else
    echo "Skipping XDP program load (not root)"
    echo "Note: XDP program may already be loaded or needs to be loaded with sudo"
fi

# Step 3: Check Python dependencies
echo "Checking Python dependencies..."
python3 -c "import subprocess; print('✓ subprocess module available')" || {
    echo "✗ Python subprocess module not found"
    exit 1
}

# Step 4: Test Python script syntax
echo "Testing Python script syntax..."
python3 -m py_compile soft_rss_reader_cli.py && echo "✓ Python script syntax OK"

# Step 5: Show usage options
echo
echo "=== Usage Examples ==="
echo
echo "1. Basic usage (requires XDP program loaded):"
echo "   python3 soft_rss_reader_cli.py -i $INTERFACE"
echo
echo "2. Custom stats interval:"
echo "   python3 soft_rss_reader_cli.py -i $INTERFACE -s 5"
echo
echo "3. Different bucket count:"
echo "   python3 soft_rss_reader_cli.py -i $INTERFACE -b 16"
echo
echo "4. Run with XDP pre-loaded by sudo:"
echo "   sudo python3 soft_rss_reader_cli.py -i $INTERFACE"
echo

# Step 6: Optional - run a quick test
read -p "Run a quick 30-second test? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Running 30-second test..."
    timeout 30s python3 soft_rss_reader_cli.py -i $INTERFACE -s 5 || echo "Test completed"
fi

echo
echo "=== Test Complete ==="
echo "To manually load XDP program:"
echo "  sudo ip link set dev $INTERFACE xdp obj $XDP_OBJECT sec xdp generic"
echo
echo "To manually unload XDP program:"
echo "  sudo ip link set dev $INTERFACE xdp off"
echo
echo "To run the reader:"
echo "  python3 soft_rss_reader_cli.py -i $INTERFACE"