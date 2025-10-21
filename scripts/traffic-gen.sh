#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}=== HTTP Traffic Generator for BPF Testing ===${NC}"
echo

# Parse command line arguments
AUTO_MODE=false
TRAFFIC_TYPE=""
DURATION=10
REQUESTS=100

while [[ $# -gt 0 ]]; do
    case $1 in
        --auto|-a)
            AUTO_MODE=true
            shift
            ;;
        --type|-t)
            TRAFFIC_TYPE="$2"
            shift 2
            ;;
        --duration|-d)
            DURATION="$2"
            shift 2
            ;;
        --requests|-r)
            REQUESTS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo
            echo "Options:"
            echo "  -a, --auto              Run automated test sequence"
            echo "  -t, --type <type>       Traffic type (http, tcp, mixed, benchmark)"
            echo "  -d, --duration <sec>    Test duration in seconds (default: 10)"
            echo "  -r, --requests <num>    Number of requests (default: 100)"
            echo "  -h, --help              Show this help message"
            echo
            echo "Traffic Types:"
            echo "  http       - HTTP GET requests"
            echo "  tcp        - Raw TCP connections"
            echo "  mixed      - Combination of different protocols"
            echo "  benchmark  - Apache Bench performance test"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to check Docker installation
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        echo "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker compose version &> /dev/null; then
        echo -e "${RED}Error: Docker Compose is not installed${NC}"
        echo "Please install Docker Compose"
        exit 1
    fi
}

# Function to start containers
start_containers() {
    echo -e "${YELLOW}Checking Docker containers...${NC}"
    cd "$PROJECT_DIR"

    CONTAINERS_RUNNING=true
    if ! docker ps | grep -q bpf-traffic-gen; then
        CONTAINERS_RUNNING=false
    fi

    if ! docker ps | grep -q bpf-target-server; then
        CONTAINERS_RUNNING=false
    fi

    if [ "$CONTAINERS_RUNNING" = false ]; then
        echo -e "${YELLOW}Starting Docker containers...${NC}"
        docker compose up -d
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to start Docker containers${NC}"
            echo "Please check docker-compose.yml configuration"
            exit 1
        fi

        echo "Waiting for containers to be ready..."
        sleep 3
    else
        echo -e "${GREEN}Containers already running${NC}"
    fi

    # Verify containers are running
    if ! docker ps | grep -q bpf-traffic-gen; then
        echo -e "${RED}Error: bpf-traffic-gen container is not running${NC}"
        exit 1
    fi

    if ! docker ps | grep -q bpf-target-server; then
        echo -e "${RED}Error: bpf-target-server container is not running${NC}"
        exit 1
    fi
}

# Function to get target server IP
get_target_ip() {
    TARGET_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bpf-target-server)
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}Error: Could not get target server IP${NC}"
        exit 1
    fi
    echo "$TARGET_IP"
}

# Function to run commands in the traffic-gen container
run_in_container() {
    docker exec bpf-traffic-gen "$@"
}

# Function to generate HTTP traffic
generate_http_traffic() {
    local target_ip=$1
    local num_requests=${2:-100}

    echo -e "${GREEN}Generating HTTP traffic (${num_requests} requests)...${NC}"
    echo "Target: http://$target_ip:8080"

    # Use different methods for variety
    echo "Sending GET requests..."
    run_in_container bash -c "
        for i in \$(seq 1 $((num_requests/4))); do
            curl -s -X GET http://$target_ip:8080/ > /dev/null
            [ \$((i % 10)) -eq 0 ] && echo \"  Sent \$i GET requests\"
        done
    "

    echo "Sending POST requests..."
    run_in_container bash -c "
        for i in \$(seq 1 $((num_requests/4))); do
            curl -s -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'data=test' http://$target_ip:8080/ > /dev/null 2>&1 || true
            [ \$((i % 10)) -eq 0 ] && echo \"  Sent \$i POST requests\"
        done
    "

    echo "Sending PUT requests..."
    run_in_container bash -c "
        for i in \$(seq 1 $((num_requests/4))); do
            curl -s -X PUT -H 'Content-Type: application/json' -d '{\"data\":\"update\"}' http://$target_ip:8080/ > /dev/null 2>&1 || true
            [ \$((i % 10)) -eq 0 ] && echo \"  Sent \$i PUT requests\"
        done
    "

    echo "Sending DELETE requests..."
    run_in_container bash -c "
        for i in \$(seq 1 $((num_requests/4))); do
            curl -s -X DELETE http://$target_ip:8080/item > /dev/null 2>&1 || true
            [ \$((i % 10)) -eq 0 ] && echo \"  Sent \$i DELETE requests\"
        done
    "
}

# Function to generate TCP traffic
generate_tcp_traffic() {
    local target_ip=$1
    local num_connections=${2:-50}

    echo -e "${GREEN}Generating raw TCP connections (${num_connections} connections)...${NC}"
    run_in_container bash -c "
        for i in \$(seq 1 $num_connections); do
            # Send a simple HTTP GET request via netcat to avoid errors
            printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 1 $target_ip 8080 >/dev/null 2>&1 || true
            [ \$((i % 10)) -eq 0 ] && echo \"  Completed \$i connections\"
        done
        echo \"  Completed $num_connections connections\"
    "
}

# Function to run Apache Bench
run_benchmark() {
    local target_ip=$1
    local requests=${2:-1000}
    local concurrency=${3:-10}

    echo -e "${GREEN}Running Apache Bench benchmark...${NC}"
    echo "Requests: $requests, Concurrency: $concurrency"
    run_in_container ab -n "$requests" -c "$concurrency" "http://$target_ip:8080/"
}

# Function to generate mixed traffic
generate_mixed_traffic() {
    local target_ip=$1
    local duration=${2:-10}

    echo -e "${GREEN}Generating mixed traffic for ${duration} seconds...${NC}"

    # Run mixed traffic generation in container
    run_in_container bash -c "
        # Start HTTP traffic in background
        (
            for i in \$(seq 1 $duration); do
                curl -s http://$target_ip:8080 >/dev/null 2>&1 &
                curl -s -X POST -d 'test=data' http://$target_ip:8080 >/dev/null 2>&1 &
                sleep 1
            done
        ) &

        # Start TCP connections in background
        (
            for i in \$(seq 1 $duration); do
                printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 1 $target_ip 8080 >/dev/null 2>&1
                sleep 1
            done
        ) &

        # Wait for duration
        sleep $duration

        # Report completion
        echo '  Mixed traffic generation completed'
    "
}

# Function to run automated test sequence
run_auto_tests() {
    local target_ip=$1

    echo -e "${BLUE}Running automated test sequence...${NC}"
    echo

    echo -e "${YELLOW}[Test 1/5] HTTP GET Requests${NC}"
    generate_http_traffic "$target_ip" 40
    echo
    sleep 2

    echo -e "${YELLOW}[Test 2/5] TCP Connections${NC}"
    generate_tcp_traffic "$target_ip" 30
    echo
    sleep 2

    echo -e "${YELLOW}[Test 3/5] Mixed HTTP Methods${NC}"
    run_in_container bash -c "
        curl -s -I http://$target_ip:8080 > /dev/null 2>&1 || true
        echo 'Sent HEAD request'
        curl -s -X OPTIONS http://$target_ip:8080 > /dev/null 2>&1 || true
        echo 'Sent OPTIONS request'
        curl -s -X PATCH -H 'Content-Type: application/json' -d '{\"field\":\"value\"}' http://$target_ip:8080 > /dev/null 2>&1 || true
        echo 'Sent PATCH request'
        curl -s -X TRACE http://$target_ip:8080 > /dev/null 2>&1 || true
        echo 'Sent TRACE request'
    "
    echo
    sleep 2

    echo -e "${YELLOW}[Test 4/5] Concurrent Requests${NC}"
    run_in_container bash -c "
        for i in {1..10}; do
            curl -s http://$target_ip:8080 > /dev/null &
        done
        wait
    "
    echo "Sent 10 concurrent requests"
    echo
    sleep 2

    echo -e "${YELLOW}[Test 5/5] Performance Benchmark${NC}"
    run_benchmark "$target_ip" 100 5
    echo
}

# Main execution
main() {
    # Check Docker installation
    check_docker

    # Start containers if needed
    start_containers

    # Get target server IP
    TARGET_IP=$(get_target_ip)
    echo -e "${GREEN}Target server IP: $TARGET_IP${NC}"
    echo

    # Run traffic generation based on options
    if [ "$AUTO_MODE" = true ]; then
        run_auto_tests "$TARGET_IP"
    elif [ -n "$TRAFFIC_TYPE" ]; then
        case $TRAFFIC_TYPE in
            http)
                generate_http_traffic "$TARGET_IP" "$REQUESTS"
                ;;
            tcp)
                generate_tcp_traffic "$TARGET_IP" "$REQUESTS"
                ;;
            benchmark)
                run_benchmark "$TARGET_IP" "$REQUESTS" 10
                ;;
            mixed)
                generate_mixed_traffic "$TARGET_IP" "$DURATION"
                ;;
            *)
                echo -e "${RED}Unknown traffic type: $TRAFFIC_TYPE${NC}"
                exit 1
                ;;
        esac
    else
        # Interactive menu
        echo "Choose traffic generation mode:"
        echo "1) HTTP requests (various methods)"
        echo "2) TCP connections"
        echo "3) Apache Bench benchmark"
        echo "4) Mixed traffic"
        echo "5) Automated test sequence"
        echo

        read -p "Enter choice (1-5): " choice

        case $choice in
            1)
                generate_http_traffic "$TARGET_IP" "$REQUESTS"
                ;;
            2)
                generate_tcp_traffic "$TARGET_IP" "$REQUESTS"
                ;;
            3)
                run_benchmark "$TARGET_IP" "$REQUESTS" 10
                ;;
            4)
                generate_mixed_traffic "$TARGET_IP" "$DURATION"
                ;;
            5)
                run_auto_tests "$TARGET_IP"
                ;;
            *)
                echo -e "${RED}Invalid choice${NC}"
                exit 1
                ;;
        esac
    fi

    echo
    echo -e "${GREEN}Traffic generation complete!${NC}"
    echo
    echo "To stop containers, run: docker compose down"
    echo "To view container logs, run: docker compose logs"
}

# Run main function
main