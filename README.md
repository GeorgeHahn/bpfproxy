# BPF Hook - HTTP Traffic Inspector

A high-performance eBPF/XDP program for monitoring and analyzing HTTP traffic at the kernel level using aya-rs.

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
# Monitor with auto-detected interface
sudo ./scripts/monitor.sh

# Or specify an interface
sudo ./scripts/monitor.sh --interface eth0
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

- **Real-time HTTP monitoring**: Captures and analyzes HTTP traffic at XDP layer
- **Multiple HTTP methods**: Tracks GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT
- **Performance metrics**: Displays request counts, bytes processed, and per-IP statistics
- **Port filtering**: Monitors HTTP traffic on ports 80, 8080, 8000, and 3000
- **Zero-copy processing**: Uses XDP for minimal performance impact

## Scripts

The project includes three main scripts in the `scripts/` directory:

### `monitor.sh` - BPF Monitor
Attaches the BPF program and displays real-time metrics:
```bash
sudo ./scripts/monitor.sh [--interface <iface>] [--metrics-interval <seconds>]
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

See [scripts/README.md](scripts/README.md) for detailed usage instructions.

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
     ./bpfhook-userspace/target/release/bpfhook --interface docker0
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

## Project Structure

- `bpfhook-userspace/` - Userspace loader program
- `bpfhook-ebpf/` - eBPF kernel program (XDP)
- `docker-compose.yml` - Test container setup
- `scripts/` - Utility scripts for monitoring and testing
  - `monitor.sh` - BPF monitoring script
  - `traffic-gen.sh` - Traffic generation script
  - `build.sh` - Build script
