#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== BPF Connection Monitor with Container Attribution ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Parse command line arguments
CGROUP_PATH="/sys/fs/cgroup"
METRICS_INTERVAL=5
SHOW_CONTAINERS=""
SHOW_EVENTS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --cgroup|-c)
            CGROUP_PATH="$2"
            shift 2
            ;;
        --metrics-interval|-m)
            METRICS_INTERVAL="$2"
            shift 2
            ;;
        --show-containers|-s)
            SHOW_CONTAINERS="--show-containers"
            shift
            ;;
        --show-events|-e)
            SHOW_EVENTS="--show-events"
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $0 [options]"
            echo
            echo "Options:"
            echo "  -c, --cgroup <path>          Cgroup path to attach to (default: /sys/fs/cgroup)"
            echo "  -m, --metrics-interval <sec> Metrics display interval (default: 5)"
            echo "  -s, --show-containers        Show individual container metrics"
            echo "  -e, --show-events            Show real-time connection events"
            echo "  -h, --help                   Show this help message"
            echo
            echo "This monitor hooks connection events (connect/accept/state changes)"
            echo "instead of network interfaces, providing container attribution."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Verify cgroup v2 is mounted
if [ ! -d "$CGROUP_PATH" ]; then
    echo "Error: Cgroup path $CGROUP_PATH does not exist"
    echo "Make sure cgroup v2 is mounted"
    exit 1
fi

# Check if it's cgroup v2
if [ ! -f "$CGROUP_PATH/cgroup.controllers" ]; then
    echo "Error: $CGROUP_PATH does not appear to be a cgroup v2 mount"
    echo "This monitor requires cgroup v2 for connection hooks"
    exit 1
fi

echo "Using cgroup path: $CGROUP_PATH"

# Show container information if Docker is available
if command -v docker &>/dev/null && docker ps -q &>/dev/null; then
    echo
    echo "Detected running containers:"
    docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Status}}" | head -10
    echo
    echo "Connection events from all containers and the host will be monitored."
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
echo "Starting BPF connection monitor..."
echo "Metrics interval: ${METRICS_INTERVAL}s"
if [ -n "$SHOW_CONTAINERS" ]; then
    echo "Container metrics: enabled"
fi
if [ -n "$SHOW_EVENTS" ]; then
    echo "Real-time events: enabled (set RUST_LOG=debug to see events)"
fi
echo "Press Ctrl+C to stop"
echo "----------------------------------------"
echo

# Set appropriate log level based on event display
if [ -n "$SHOW_EVENTS" ]; then
    LOG_LEVEL="debug"
else
    LOG_LEVEL="info"
fi

# Run the BPF program
EBPF_PATH="$EBPF_BINARY" \
RUST_LOG="$LOG_LEVEL" \
exec "$USERSPACE_BINARY" \
    --cgroup-path "$CGROUP_PATH" \
    --metrics-interval "$METRICS_INTERVAL" \
    $SHOW_CONTAINERS \
    $SHOW_EVENTS