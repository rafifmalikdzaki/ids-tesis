#!/bin/bash
# Deployment script for XDP Software RSS system

set -e

INTERFACE="wlo1"
XDP_OBJECT="xdp_soft_rss.o"
MAX_BUCKETS=8

echo "=========================================="
echo "XDP Software RSS Deployment Script"
echo "=========================================="
echo "Interface: $INTERFACE"
echo "Buckets: $MAX_BUCKETS"
echo "=========================================="

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
echo "Checking dependencies..."

if ! command_exists clang; then
    echo "❌ clang not found. Install with: sudo apt-get install clang"
    exit 1
fi
echo "✓ clang found"

if ! command_exists ip; then
    echo "❌ iproute2 not found. Install with: sudo apt-get install iproute2"
    exit 1
fi
echo "✓ iproute2 found"

if ! python3 -c "import bcc" 2>/dev/null; then
    echo "❌ Python BCC module not found. Install with: sudo apt-get install python3-bpfcc"
    exit 1
fi
echo "✓ Python BCC module found"

if ! command_exists argus; then
    echo "⚠️  Argus not found. Install with: sudo apt-get install argus-client"
    echo "   (Argus is optional for basic flow monitoring)"
fi

# Check if interface exists
if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "❌ Interface $INTERFACE not found"
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
    exit 1
fi
echo "✓ Interface $INTERFACE found"

# Compile XDP program with BTF compatibility
compile_xdp_program() {
    local obj_file=$1
    local compile_method=$2

    echo "Compiling XDP program ($compile_method)..."

    case $compile_method in
        "debug")
            clang -g -O2 -target bpf -c xdp_soft_rss.c -o "$obj_file" 2>/dev/null
            ;;
        "simple_flags")
            clang -target bpf -O2 -c xdp_soft_rss.c -o "$obj_file" 2>/dev/null
            ;;
        "simple_program")
            clang -O2 -target bpf -c xdp_simple_rss.c -o "$obj_file" 2>/dev/null
            ;;
        *)
            clang -O2 -target bpf -c xdp_soft_rss.c -o "$obj_file" 2>/dev/null
            ;;
    esac

    return $?
}

# Try to find a working XDP compilation
find_working_xdp() {
    local methods=("debug" "simple_flags" "simple_program" "original")
    local files=("xdp_soft_rss_debug.o" "xdp_soft_rss_simple.o" "xdp_simple_rss.o" "xdp_soft_rss.o")

    echo "🔨 Testing XDP compilation methods for BTF compatibility..."

    for i in "${!methods[@]}"; do
        local method="${methods[$i]}"
        local file="${files[$i]}"

        echo "  Testing method: $method"

        if compile_xdp_program "$file" "$method"; then
            echo "    ✓ Compiled successfully: $file"

            # Test if it can be loaded (if running as root)
            if [[ $EUID -eq 0 ]]; then
                echo "    Testing XDP loading..."
                ip link set dev "$INTERFACE" xdp off 2>/dev/null || true

                if ip link set dev "$INTERFACE" xdp obj "$file" sec xdp generic 2>/dev/null; then
                    echo "    ✅ Successfully loaded! Using $file"
                    ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
                    XDP_OBJECT="$file"
                    return 0
                else
                    echo "    ❌ Failed to load"
                fi
            else
                echo "    ℹ️  Compilation succeeded (will test loading later)"
                XDP_OBJECT="$file"
                return 0
            fi
        else
            echo "    ❌ Compilation failed"
        fi
    done

    echo "❌ All XDP compilation methods failed"
    return 1
}

# Check if we already have a working XDP object
if [[ -f "$XDP_OBJECT" ]]; then
    echo "✓ XDP object found: $XDP_OBJECT"
else
    if find_working_xdp; then
        echo "✓ Found working XDP compilation: $XDP_OBJECT"
    else
        echo "❌ Failed to compile any working XDP program"
        echo ""
        echo "Troubleshooting tips:"
        echo "1. Ensure you have the correct kernel headers: sudo apt-get install linux-headers-\$(uname -r)"
        echo "2. Try a different kernel version"
        echo "3. Run the test script: ./test_xdp_loading.sh"
        exit 1
    fi
fi

# Show deployment options
echo ""
echo "=========================================="
echo "DEPLOYMENT OPTIONS"
echo "=========================================="
echo ""
echo "1. Basic Flow Monitoring (recommended for testing):"
echo "   sudo python3 soft_rss_reader.py -i $INTERFACE"
echo ""
echo "2. Flow Monitoring with Statistics (every 5 seconds):"
echo "   sudo python3 soft_rss_reader.py -i $INTERFACE -s 5"
echo ""
echo "3. Flow Monitoring with State Persistence:"
echo "   sudo python3 soft_rss_reader.py -i $INTERFACE -o rss_state.json"
echo ""
echo "4. Argus Integration (requires Argus):"
echo "   sudo python3 argus_integration.py -i $INTERFACE -b $MAX_BUCKETS"
echo ""
echo "5. Demo Mode (no root required):"
echo "   python3 demo_soft_rss.py"
echo ""
echo "6. Test System:"
echo "   ./test_soft_rss.sh"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "🔧 Running as root - can manage XDP programs"

    read -p "Load XDP program now? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Loading XDP program..."
        ip link set dev "$INTERFACE" xdp off 2>/dev/null || true
        ip link set dev "$INTERFACE" xdp obj "$XDP_OBJECT" sec xdp generic

        if bpftool prog show | grep -q "xdp"; then
            echo "✅ XDP program loaded successfully"
            echo ""
            echo "XDP program info:"
            bpftool prog show
            echo ""
            echo "Ready to run flow monitoring!"
            echo "Start with: sudo python3 soft_rss_reader.py -i $INTERFACE"
        else
            echo "❌ Failed to load XDP program"
            exit 1
        fi
    fi
else
    echo "ℹ️  Running as user - XDP program must be loaded by root"
    echo "   Load with: sudo ip link set dev $INTERFACE xdp obj $XDP_OBJECT sec xdp generic"
fi

echo ""
echo "=========================================="
echo "DEPLOYMENT COMPLETE"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Load XDP program (if not done)"
echo "2. Run flow monitoring: sudo python3 soft_rss_reader.py -i $INTERFACE"
echo "3. Optionally run Argus integration: sudo python3 argus_integration.py -i $INTERFACE"
echo ""
echo "To unload XDP program:"
echo "   sudo ip link set dev $INTERFACE xdp off"
echo ""
echo "For troubleshooting, see README.md"