#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

echo "=== BPFHook Container Proxy Test ==="
echo
echo "This script demonstrates incoming connection interception to containers"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Parse command line arguments
CONTAINER_NAME=""
PROXY_ADDR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        --proxy)
            PROXY_ADDR="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: sudo $0 [options]"
            echo
            echo "Options:"
            echo "  --container <name>  Container to intercept (intercept incoming connections to this container)"
            echo "  --proxy <IP:PORT>   Proxy address to redirect intercepted connections to"
            echo "  --help              Show this help message"
            echo
            echo "Examples:"
            echo "  # Monitor all connections:"
            echo "  sudo $0"
            echo
            echo "  # Intercept incoming connections to 'target-server' container:"
            echo "  sudo $0 --container target-server"
            echo
            echo "  # Redirect intercepted connections to proxy:"
            echo "  sudo $0 --proxy 172.17.0.4:8888"
            echo
            echo "  # Intercept connections to 'target-server' AND redirect to proxy:"
            echo "  sudo $0 --container target-server --proxy 172.17.0.4:8888"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build the project first
echo "Building BPF programs..."
if ! sudo -u "${SUDO_USER:-$USER}" "$SCRIPT_DIR/scripts/build.sh"; then
    echo "Failed to build BPF programs"
    exit 1
fi

# Build command line arguments
CMD_ARGS=""

if [ -n "$CONTAINER_NAME" ]; then
    # Check if container exists
    if docker ps -q --filter "name=$CONTAINER_NAME" > /dev/null 2>&1; then
        echo "✓ Found container: $CONTAINER_NAME"
        CMD_ARGS="$CMD_ARGS --container $CONTAINER_NAME"
    else
        echo "Error: Container '$CONTAINER_NAME' not found or not running"
        echo "Available containers:"
        docker ps --format "table {{.Names}}\t{{.Status}}"
        exit 1
    fi
fi

if [ -n "$PROXY_ADDR" ]; then
    echo "✓ Proxy redirection to: $PROXY_ADDR"
    CMD_ARGS="$CMD_ARGS --proxy $PROXY_ADDR"
fi

echo
echo "Starting BPFHook with configuration:"
echo "  Container filter: ${CONTAINER_NAME:-<none>}"
echo "  Proxy redirect:   ${PROXY_ADDR:-<none>}"
echo
echo "Press Ctrl+C to stop"
echo "----------------------------------------"

# Verify binaries exist
EBPF_BINARY="$PROJECT_DIR/bpfhook-ebpf/target/bpfel-unknown-none/release/bpfhook"
USERSPACE_BINARY="$PROJECT_DIR/bpfhook-userspace/target/release/bpfhook"

if [ ! -f "$EBPF_BINARY" ] || [ ! -f "$USERSPACE_BINARY" ]; then
    echo "Error: BPF binaries not found after build"
    exit 1
fi

# Run the BPF program
EBPF_PATH="$EBPF_BINARY" \
RUST_LOG=info \
exec "$USERSPACE_BINARY" \
    --cgroup-path /sys/fs/cgroup \
    --show-events \
    $CMD_ARGS