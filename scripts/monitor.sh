#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== BPF HTTP Traffic Monitor ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Parse command line arguments
INTERFACE=""
METRICS_INTERVAL=5

while [[ $# -gt 0 ]]; do
    case $1 in
        --interface|-i)
            INTERFACE="$2"
            shift 2
            ;;
        --metrics-interval|-m)
            METRICS_INTERVAL="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: sudo $0 [options]"
            echo
            echo "Options:"
            echo "  -i, --interface <iface>      Interface to attach to (default: auto-detect)"
            echo "  -m, --metrics-interval <sec> Metrics display interval (default: 5)"
            echo "  -h, --help                   Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Function to find the veth interface for a specific container
find_container_veth() {
    local container_name=$1

    # Check if container exists and is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        return 1
    fi

    # Get container's PID
    local container_pid=$(docker inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null)
    if [ -z "$container_pid" ]; then
        return 1
    fi

    # Get the peer interface index from inside the container
    local peer_index=$(nsenter -t "$container_pid" -n ip link show eth0 2>/dev/null | sed -n 's/.*@if\([0-9]*\):.*/\1/p')
    if [ -z "$peer_index" ]; then
        return 1
    fi

    # Find the veth interface on the host with this index
    local veth_interface=$(ip link show | grep "^${peer_index}:" | cut -d: -f2 | cut -d@ -f1 | tr -d ' ')
    if [ -n "$veth_interface" ]; then
        echo "$veth_interface"
        return 0
    fi

    return 1
}

# Auto-detect interface if not specified
if [ -z "$INTERFACE" ]; then
    echo "Detecting best interface for monitoring..."

    # First, try to find the veth for bpf-target-server (where we want to see incoming traffic)
    if command -v docker &>/dev/null; then
        TARGET_VETH=$(find_container_veth "bpf-target-server")
        if [ -n "$TARGET_VETH" ]; then
            INTERFACE="$TARGET_VETH"
            echo "Found bpf-target-server veth interface: $INTERFACE"
        else
            # Try traffic-gen container as backup
            GEN_VETH=$(find_container_veth "bpf-traffic-gen")
            if [ -n "$GEN_VETH" ]; then
                INTERFACE="$GEN_VETH"
                echo "Found bpf-traffic-gen veth interface: $INTERFACE"
            fi
        fi
    fi

    # If we couldn't find container veths, fall back to any veth
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip link show | grep -E 'veth.*master docker0' | head -1 | cut -d: -f2 | cut -d@ -f1 | tr -d ' ')
        if [ -n "$INTERFACE" ]; then
            echo "Using first available veth interface: $INTERFACE"
        fi
    fi

    # If no veth, try docker0
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip link show | grep -o 'docker[0-9]*' | head -1)
        if [ -n "$INTERFACE" ]; then
            echo "Warning: Using docker0 bridge (may not see all traffic): $INTERFACE"
        fi
    fi

    # If no docker, use default interface
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        if [ -n "$INTERFACE" ]; then
            echo "Using default network interface: $INTERFACE"
        fi
    fi

    if [ -z "$INTERFACE" ]; then
        echo "Error: Could not auto-detect network interface"
        echo "Available interfaces:"
        ip link show | grep -E '^[0-9]+:' | grep -v 'lo:' | awk '{print "  - " $2}' | sed 's/:$//'
        exit 1
    fi
else
    echo "Using specified interface: $INTERFACE"
fi

# Show which container this veth belongs to (if applicable)
if echo "$INTERFACE" | grep -q "^veth"; then
    echo
    echo "Container interface mapping:"
    for container in bpf-target-server bpf-traffic-gen; do
        if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
            CONTAINER_VETH=$(find_container_veth "$container")
            if [ "$CONTAINER_VETH" = "$INTERFACE" ]; then
                echo "  -> Monitoring traffic for container: $container"
            fi
        fi
    done
fi

# Verify interface exists
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "Error: Interface $INTERFACE does not exist"
    exit 1
fi

# Always rebuild to ensure latest changes
echo
echo "Building BPF programs..."
if ! sudo -u "${SUDO_USER:-$USER}" "$SCRIPT_DIR/build.sh"; then
    echo "Failed to build BPF programs"
    exit 1
fi

# Verify binaries exist
EBPF_BINARY="$PROJECT_DIR/bpfhook-ebpf/target/bpfel-unknown-none/release/bpfhook"
USERSPACE_BINARY="$PROJECT_DIR/bpfhook-userspace/target/release/bpfhook"

if [ ! -f "$EBPF_BINARY" ] || [ ! -f "$USERSPACE_BINARY" ]; then
    echo "Error: BPF binaries not found after build"
    exit 1
fi

echo
echo "Starting BPF monitor on $INTERFACE..."
echo "Metrics interval: ${METRICS_INTERVAL}s"
echo "Press Ctrl+C to stop"
echo "----------------------------------------"
echo

# Run the BPF program
EBPF_PATH="$EBPF_BINARY" \
RUST_LOG=info \
exec "$USERSPACE_BINARY" \
    --interface "$INTERFACE" \
    --metrics-interval "$METRICS_INTERVAL"