# BPF Hook - Connection Monitor with Container Attribution

A collection of concepts for container traffic snooping. The goal here was to transparently capture a specific container's incoming network and UDS traffic for later replay and analysis.

## Proofs of Concept

A BPF program for monitoring network connections with container attribution.

A simpler TC mirred-based traffic mirroring approach for packet-level traffic observation without eBPF (see [TC Mirred section](#tc-mirred-traffic-mirroring-non-bpf-alternative)).

## BPF Hook Architecture

- **Inbound connections**: `kprobe` on `inet_csk_accept` for accepted connections
- **State changes**: `tracepoint sock:inet_sock_set_state` for tracking connection lifecycle
- **Container attribution**: Uses cgroup ID (`bpf_get_current_cgroup_id()`) and network namespace cookies (`bpf_get_netns_cookie()`)

**Note**: Currently only IPv4 connections are monitored.

Aims to provide
- Interface-independent monitoring
- Container/process attribution
- Connection lifecycle tracking
- Support for all network topologies (veth, bridge, host networking)

## Prerequisites

```bash
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

## Quick Start

### 1. Build the Project
```bash
./scripts/build.sh
```

### 2. Start Monitoring
```bash
# Monitor all connections (host + containers)
sudo ./scripts/monitor.sh

# Show individual container metrics
sudo ./scripts/monitor.sh --show-containers

# Show real-time connection events
sudo ./scripts/monitor.sh --show-events

# Custom cgroup path (default: /sys/fs/cgroup)
sudo ./scripts/monitor.sh --cgroup /path/to/cgroup
```

### 3. Generate Test Traffic
In another terminal:
```bash
# Run automated test sequence
./scripts/traffic-gen.sh --auto

# Or choose specific traffic type
./scripts/traffic-gen.sh --type http --requests 500
```

## Features

- **Connection-event based monitoring**: Hooks connect/accept/state changes instead of interfaces
- **Container attribution**: Automatically identifies container vs host connections
- **Connection lifecycle tracking**: Monitors connections from SYN_SENT to CLOSE
- **Cgroup-based metrics**: Aggregates metrics by cgroup ID
- **Network namespace awareness**: Tracks connections by network namespace
- **Real-time events**: Optional live connection event stream
- **Zero interface dependency**: Works regardless of network topology

## How It Works

### Hook Points

1. **cgroup/connect4**: Intercepts outbound IPv4 connection attempts
2. **sock:inet_sock_set_state**: Tracks all TCP state transitions
3. **inet_csk_accept**: Captures inbound connection accepts

**Note**: IPv6 connections (cgroup/connect6) are not currently monitored.

### Container Attribution

The monitor identifies containers through:
- **Cgroup ID**: Each container runs in its own cgroup
- **Network namespace cookie**: Unique identifier for network namespaces
- **Process ID**: Links connections to specific processes

## Scripts

The project includes utility scripts in the `scripts/` directory:

### `monitor.sh` - Connection Monitor
Attaches the eBPF programs and displays connection metrics:
```bash
sudo ./scripts/monitor.sh [options]
  -c, --cgroup <path>          Cgroup path to attach to (default: /sys/fs/cgroup)
  -m, --metrics-interval <sec> Metrics display interval (default: 5)
  -s, --show-containers        Show individual container metrics
  -e, --show-events            Show real-time connection events
```

### `traffic-gen.sh` - Traffic Generator
Generates various types of test traffic:
```bash
./scripts/traffic-gen.sh [--auto] [--type <type>] [--requests <num>]
```

### `build.sh` - Build Script
Builds both eBPF and userspace components:
```bash
./scripts/build.sh
```

## Manual Usage

If you prefer to run the components manually:

### Build
```bash
# Build eBPF program
cd bpfhook-ebpf
cargo build --release

# Build userspace program
cd ../bpfhook-userspace
cargo build --release
```

### Run
```bash
# Set the eBPF program path and run
sudo EBPF_PATH=./bpfhook-ebpf/target/bpfel-unknown-none/release/bpfhook \
     RUST_LOG=info \
     ./bpfhook-userspace/target/release/bpfhook \
     --cgroup-path /sys/fs/cgroup \
     --show-containers
```

## TC Mirred Traffic Mirroring (Non-BPF Alternative)

This repository also includes a simpler, non-BPF approach for traffic observation using Linux Traffic Control (`tc`) with the `mirred` action. This method mirrors network packets from one container to another for analysis.

### Overview

The TC mirred approach provides packet-level traffic mirroring without requiring eBPF:
- Uses standard Linux `tc` (traffic control) commands
- Mirrors traffic at the veth interface level
- No kernel programming or eBPF required
- Suitable for packet inspection and traffic analysis scenarios

### Architecture

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  Client  │────────►│  Server  │         │ Observer │
│Container │         │Container │         │Container │
└──────────┘         └────┬─────┘         └────▲─────┘
                          │                     │
                     veth interface         veth interface
                          │                     │
                     ┌────▼─────────────────────┴────┐
                     │   tc mirred rules             │
                     │   (mirror packets)            │
                     └────────────────────────────────┘
```

### Quick Start

```bash
# Run the TC mirred demo
sudo ./demo_tc_mirror.sh
```

This script will:
1. Start three containers (client, server, observer)
2. Set up TC mirred rules to mirror traffic from server to observer
3. Demonstrate traffic mirroring with live packet capture
4. Clean up automatically on exit

### How It Works

1. **Veth Interface Discovery**: The script automatically discovers the veth interfaces for containers
2. **TC Rule Configuration**: Sets up ingress and egress qdiscs with mirred actions
3. **Packet Mirroring**: All packets passing through the server's veth are copied to the observer's veth
4. **Traffic Analysis**: The observer container can run tcpdump or any packet analysis tool

### Manual Usage

```bash
# Start containers
docker compose -f docker-compose-tc.yml up -d

# Find veth interfaces
SERVER_VETH=$(docker exec tc-server cat /sys/class/net/eth0/iflink)
OBSERVER_VETH=$(docker exec tc-observer cat /sys/class/net/eth0/iflink)

# Set up mirroring (ingress)
tc qdisc add dev veth${SERVER_VETH} ingress
tc filter add dev veth${SERVER_VETH} ingress \
    protocol all prio 1 matchall \
    action mirred egress mirror dev veth${OBSERVER_VETH}

# Set up mirroring (egress)
tc qdisc add dev veth${SERVER_VETH} root handle 1: prio
tc filter add dev veth${SERVER_VETH} parent 1: \
    protocol all prio 1 matchall \
    action mirred egress mirror dev veth${OBSERVER_VETH}

# Monitor in observer container
docker exec -it tc-observer tcpdump -i eth0 -nn
```

### Use Cases

The TC mirred approach is ideal for:
- **Traffic Analysis**: Inspect packets without modifying application code
- **Debugging**: Observe actual network traffic between containers
- **Security Monitoring**: Non-invasive traffic inspection
- **Protocol Analysis**: Capture and analyze application protocols

### Comparison with eBPF Approach

| Feature | eBPF Monitoring | TC Mirred |
|---------|----------------|-----------|
| **Complexity** | High (requires kernel programming) | Low (standard Linux commands) |
| **Performance** | Very high (in-kernel processing) | Good (packet copying overhead) |
| **Granularity** | Connection-level with metrics | Packet-level raw data |
| **Attribution** | Process/container attribution | No process attribution |
| **Filtering** | Programmable in-kernel filters | Basic TC filters |
| **Use Case** | Connection monitoring & metrics | Packet inspection & analysis |

### Requirements

- Linux kernel with TC support (standard in all modern distributions)
- Docker or container runtime
- Root privileges for TC configuration
- iproute2 package (provides `tc` command)

## Docker Test Environment

The project includes Docker containers for testing:

### Container Management
```bash
# Start containers
docker compose up -d

# Stop containers
docker compose down

# View container logs
docker compose logs -f

# Get container IPs
docker inspect bpf-traffic-gen | grep IPAddress
docker inspect bpf-target-server | grep IPAddress
```

## Output Example

```
CONNECTION METRICS REPORT
================================================================================

Active Connections:
--------------------------------------------------------------------------------
  Total: 15 (Host: 3, Container: 12)

  By State:
    ESTABLISHED     8
    TIME_WAIT       4
    SYN_SENT        2
    CLOSE_WAIT      1

  Recent Connections (showing first 5):
    PID:1234     10.0.2.15:45678 -> 142.251.46.142:443 (ESTABLISHED) [CTR]
    PID:5678     172.17.0.2:56789 -> 172.17.0.3:80 (TIME_WAIT) [CTR]
    PID:91011    10.0.2.15:34567 -> 8.8.8.8:53 (ESTABLISHED)

Cgroup-based Metrics:
--------------------------------------------------------------------------------
  Aggregate Metrics:
    Total Connections:  523
    Active Connections: 15
================================================================================
```

## Project Structure

- `bpfhook-userspace/` - Userspace loader and monitor program
- `bpfhook-ebpf/` - eBPF kernel programs (cgroup, tracepoint, kprobe)
- `docker-compose-tc.yml` - Test container setup for TC mirred demo
- `demo_tc_mirror.sh` - TC mirred traffic mirroring demo script
- `scripts/` - Utility scripts for monitoring and testing
  - `monitor.sh` - Connection monitoring script
  - `traffic-gen.sh` - Traffic generation script
  - `build.sh` - Build script

## Technical Details

### Data Structures

**ConnectionInfo**: Tracks individual connections
- Process ID/Thread ID
- Cgroup ID and network namespace cookie
- Source/destination addresses and ports
- TCP state and timestamp
- Container flag

**ConnectionMetrics**: Aggregated metrics per cgroup
- Total and active connection counts
- Bytes sent/received
- HTTP request statistics (if applicable)

### Maps

- `CONNECTION_MAP`: LRU map tracking active connections
- `METRICS_BY_CGROUP`: Metrics aggregated by cgroup ID
- `METRICS_BY_NETNS`: Metrics aggregated by network namespace
- `CONNECTION_EVENTS`: Perf event array for real-time events

## Requirements

- Linux kernel 5.0+ with eBPF support
- Cgroup v2 mounted (standard on modern distributions)
- Root privileges for eBPF attachment
- Rust toolchain with nightly compiler