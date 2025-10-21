# BPF Hook - Connection Monitor with Container Attribution

A high-performance eBPF program for monitoring network connections with container attribution, using connection-event hooks instead of interface-based monitoring.

## Architecture

This monitor follows **eBPF best practices** by hooking connection events directly rather than interfaces:

- **Outbound connections**: `cgroup/connect4` hook for IPv4 (BPF_CGROUP_SOCK_ADDR)
- **State changes**: `tracepoint sock:inet_sock_set_state` for tracking connection lifecycle
- **Inbound connections**: `kprobe` on `inet_csk_accept` for accepted connections
- **Container attribution**: Uses cgroup ID (`bpf_get_current_cgroup_id()`) and network namespace cookies (`bpf_get_netns_cookie()`)

**Note**: Currently only IPv4 connections are monitored. IPv6 support is planned for a future release.

This approach provides:
- ✅ Interface-independent monitoring
- ✅ Container/process attribution
- ✅ Connection lifecycle tracking
- ✅ Works across all network topologies (veth, bridge, host networking)

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
- `docker-compose.yml` - Test container setup
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