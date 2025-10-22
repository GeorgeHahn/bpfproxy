#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

echo "=========================================="
echo "TC Mirror Traffic Demo"
echo "=========================================="
echo "Using tc mirred to mirror traffic from server to observer"
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
CYAN='\033[0;36m'
NC='\033[0m' # No Color

cleanup() {
    echo
    echo -e "${YELLOW}Cleaning up...${NC}"

    # Remove tc rules
    echo "Removing tc rules..."
    if [ ! -z "${SERVER_VETH:-}" ]; then
        tc qdisc del dev "$SERVER_VETH" ingress 2>/dev/null || true
        tc qdisc del dev "$SERVER_VETH" root 2>/dev/null || true
    fi

    # Stop tcpdump if running
    if [ ! -z "${TCPDUMP_PID:-}" ]; then
        kill $TCPDUMP_PID 2>/dev/null || true
    fi

    echo -e "${GREEN}Cleanup complete!${NC}"
}

# Set trap for cleanup on exit
trap cleanup EXIT

echo -e "${BLUE}Step 1: Starting Docker containers...${NC}"
docker compose -f docker-compose-tc.yml down 2>/dev/null || true
docker compose -f docker-compose-tc.yml up -d
echo "Waiting for containers to start..."
sleep 5

# Get container IPs and network details
CLIENT_IP=$(docker inspect tc-client -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
SERVER_IP=$(docker inspect tc-server -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
OBSERVER_IP=$(docker inspect tc-observer -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

echo
echo -e "${GREEN}Container IPs:${NC}"
echo "  Client:   $CLIENT_IP"
echo "  Server:   $SERVER_IP (nginx)"
echo "  Observer: $OBSERVER_IP"
echo

# Find veth interfaces
echo -e "${BLUE}Step 2: Finding veth interfaces...${NC}"

# Get interface index from inside each container using docker exec
SERVER_IF_INDEX=$(docker exec tc-server cat /sys/class/net/eth0/iflink 2>/dev/null)
OBSERVER_IF_INDEX=$(docker exec tc-observer cat /sys/class/net/eth0/iflink 2>/dev/null)

if [ -z "$SERVER_IF_INDEX" ] || [ -z "$OBSERVER_IF_INDEX" ]; then
    echo -e "${RED}Error: Could not get interface indices from containers${NC}"
    exit 1
fi

# Find the corresponding veth interfaces on the host
SERVER_VETH=$(ip link | grep "^${SERVER_IF_INDEX}:" | awk '{print $2}' | cut -d@ -f1)
OBSERVER_VETH=$(ip link | grep "^${OBSERVER_IF_INDEX}:" | awk '{print $2}' | cut -d@ -f1)

echo "Server veth interface: $SERVER_VETH"
echo "Observer veth interface: $OBSERVER_VETH"

if [ -z "$SERVER_VETH" ] || [ -z "$OBSERVER_VETH" ]; then
    echo -e "${RED}Error: Could not find veth interfaces${NC}"
    exit 1
fi

echo
echo -e "${BLUE}Step 3: Testing normal traffic (before mirroring)${NC}"
echo "Making a request from client to server..."
docker exec tc-client curl -s http://$SERVER_IP/ | head -5
echo "...output truncated..."
echo

echo -e "${YELLOW}Step 4: Setting up tc mirred rules${NC}"
echo "This will mirror all traffic from server's veth to observer's veth"

# Add ingress qdisc to server interface
echo "Adding ingress qdisc to $SERVER_VETH..."
tc qdisc add dev "$SERVER_VETH" ingress 2>/dev/null || \
    (tc qdisc del dev "$SERVER_VETH" ingress 2>/dev/null; tc qdisc add dev "$SERVER_VETH" ingress)

# Add mirror rule for incoming traffic to server (from client)
echo "Adding mirror rule for incoming traffic..."
tc filter add dev "$SERVER_VETH" ingress \
    protocol all \
    prio 1 \
    matchall \
    action mirred egress mirror dev "$OBSERVER_VETH"

# Add egress qdisc and mirror for outgoing traffic from server
echo "Adding egress qdisc to $SERVER_VETH..."
tc qdisc add dev "$SERVER_VETH" root handle 1: prio 2>/dev/null || \
    (tc qdisc del dev "$SERVER_VETH" root 2>/dev/null; tc qdisc add dev "$SERVER_VETH" root handle 1: prio)

echo "Adding mirror rule for outgoing traffic..."
tc filter add dev "$SERVER_VETH" \
    parent 1: \
    protocol all \
    prio 1 \
    matchall \
    action mirred egress mirror dev "$OBSERVER_VETH"

echo -e "${GREEN}TC mirred rules configured!${NC}"
echo

# Show the rules
echo -e "${CYAN}Current TC rules:${NC}"
echo "Ingress filters on $SERVER_VETH:"
tc filter show dev "$SERVER_VETH" ingress
echo
echo "Egress filters on $SERVER_VETH:"
tc filter show dev "$SERVER_VETH" parent 1:
echo

echo -e "${BLUE}Step 5: Starting packet capture in observer container${NC}"
echo "Starting tcpdump in observer container to see mirrored traffic..."

# Start tcpdump in observer container in background
docker exec -d tc-observer sh -c "tcpdump -i eth0 -nn -l 'host $SERVER_IP' 2>/dev/null | head -20" > /tmp/observer_capture.txt &
TCPDUMP_PID=$!

# Alternative: Run tcpdump directly
docker exec tc-observer timeout 10 tcpdump -i eth0 -nn -c 20 "host $SERVER_IP or host $CLIENT_IP" 2>/dev/null &

echo
echo -e "${BLUE}Step 6: Generating traffic from client to server${NC}"
echo "The observer should see this mirrored traffic..."
echo

# Generate some traffic
for i in {1..3}; do
    echo -e "${GREEN}Request $i:${NC}"
    echo "Client sending request to server..."
    docker exec tc-client curl -s -o /dev/null -w "HTTP Status: %{http_code}, Time: %{time_total}s\n" http://$SERVER_IP/
    sleep 1
done

echo
echo -e "${BLUE}Step 7: Checking statistics${NC}"
echo "TC statistics for mirroring:"
tc -s filter show dev "$SERVER_VETH" ingress
echo

echo -e "${YELLOW}Step 8: Verifying mirrored traffic in observer${NC}"
echo "Running tcpdump in observer to show captured packets..."
docker exec tc-observer timeout 5 sh -c "tcpdump -i eth0 -nn -c 10 'host $SERVER_IP' 2>/dev/null" || true

echo
echo -e "${BLUE}Step 9: Interactive test${NC}"
echo "You can now test the mirroring yourself:"
echo
echo -e "${CYAN}In one terminal, run tcpdump in the observer:${NC}"
echo "  docker exec -it tc-observer tcpdump -i eth0 -nn 'host $SERVER_IP'"
echo
echo -e "${CYAN}In another terminal, generate traffic from client:${NC}"
echo "  docker exec tc-client curl http://$SERVER_IP/"
echo
echo -e "${GREEN}The observer should see all packets between client and server!${NC}"
echo

echo -e "${GREEN}✓ Demo setup complete!${NC}"
echo
echo -e "${YELLOW}Note: Traffic is now being mirrored from server to observer.${NC}"
echo -e "${YELLOW}The tc rules will be cleaned up when this script exits.${NC}"
echo
echo -e "${BLUE}To stop the demo and cleanup:${NC}"
echo "  Press Ctrl+C or run: docker compose -f docker-compose-tc.yml down"
echo
echo "Press Enter to continue running (tc rules stay active), or Ctrl+C to cleanup and exit..."
read -r