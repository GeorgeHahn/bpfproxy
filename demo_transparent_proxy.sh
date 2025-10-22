#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

echo "=========================================="
echo "BPFHook Transparent Proxy Demo"
echo "=========================================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Step 1: Starting Docker containers...${NC}"
docker compose down 2>/dev/null || true
docker compose up -d --build

# Wait for containers to be ready
echo -e "${BLUE}Waiting for containers to start...${NC}"
sleep 5

# Get container IPs
PROXY_IP=$(docker inspect proxy-server -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
TARGET_IP=$(docker inspect target-server -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
CLIENT_IP=$(docker inspect source-client -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

echo
echo -e "${GREEN}Container IPs:${NC}"
echo "  Source Client:  $CLIENT_IP"
echo "  Target Server:  $TARGET_IP"
echo "  Proxy Server:   $PROXY_IP"
echo

echo -e "${BLUE}Step 2: Testing normal connection (without interception)${NC}"
echo "Making a request from source-client to target-server..."
docker exec source-client curl -s http://target-server:8080/test | jq '.' 2>/dev/null || docker exec source-client curl -s http://target-server:8080/test
echo

echo -e "${YELLOW}Step 3: Starting BPFHook with transparent proxy redirection${NC}"
echo "This will intercept incoming connections to 'target-server' container"
echo "and redirect them to the proxy at ${PROXY_IP}:8888"
echo

# Build BPF programs
echo "Building BPF programs..."
if ! sudo -u "${SUDO_USER:-$USER}" "$SCRIPT_DIR/scripts/build.sh" > /dev/null 2>&1; then
    echo "Failed to build BPF programs"
    exit 1
fi

# Start BPFHook in background
echo -e "${GREEN}Starting BPFHook interceptor...${NC}"
EBPF_BINARY="$PROJECT_DIR/bpfhook-ebpf/target/bpfel-unknown-none/release/bpfhook"
USERSPACE_BINARY="$PROJECT_DIR/bpfhook-userspace/target/release/bpfhook"

EBPF_PATH="$EBPF_BINARY" \
RUST_LOG=info \
"$USERSPACE_BINARY" \
    --cgroup-path /sys/fs/cgroup \
    --container target-server \
    --proxy "${PROXY_IP}:8888" \
    --show-events &

BPFHOOK_PID=$!

# Wait for BPFHook to initialize
sleep 3

echo
echo -e "${BLUE}Step 4: Testing intercepted connection${NC}"
echo "Making the same request - it should now go through the proxy..."
echo

# Show proxy logs in another terminal or tail them
echo -e "${YELLOW}Proxy logs:${NC}"
docker logs proxy-server --tail=0 -f &
PROXY_LOG_PID=$!

sleep 1

echo
echo -e "${GREEN}Sending request from client...${NC}"
docker exec source-client curl -s http://target-server:8080/intercepted | jq '.' 2>/dev/null || docker exec source-client curl -s http://target-server:8080/intercepted

sleep 2

echo
echo -e "${BLUE}Step 5: Multiple requests to show interception${NC}"
for i in {1..3}; do
    echo -e "${GREEN}Request $i:${NC}"
    docker exec source-client curl -s http://target-server:8080/test$i > /dev/null 2>&1
    sleep 1
done

echo
echo -e "${YELLOW}Check the proxy logs above - you should see:${NC}"
echo "  - Original destination being intercepted"
echo "  - Requests being forwarded to the target server"
echo "  - Responses being sent back to the client"
echo

sleep 2

# Stop the proxy log tailing
kill $PROXY_LOG_PID 2>/dev/null || true

echo -e "${GREEN}✓ Demo complete!${NC}"
echo

# Stop BPFHook
echo -e "${BLUE}Stopping BPFHook...${NC}"
kill $BPFHOOK_PID 2>/dev/null || true
wait $BPFHOOK_PID 2>/dev/null || true

echo -e "${GREEN}✓ BPFHook stopped${NC}"
echo

echo -e "${BLUE}Containers are still running. To stop them:${NC}"
echo "  docker compose down"
echo
echo -e "${BLUE}To run the demo again:${NC}"
echo "  sudo $0"
echo