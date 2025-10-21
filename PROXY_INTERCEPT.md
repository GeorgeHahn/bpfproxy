# BPFHook Proxy Interceptor

## Overview

BPFHook has been modified to focus exclusively on **outbound connection interception** with the ability to:
1. **Filter by container name** - Only intercept connections from specific containers
2. **Redirect to proxy** - Transparently redirect connections to a proxy server

## Key Changes

### Removed Features
- Inbound connection tracking (`inet_csk_accept` kprobe)
- IPv6 support (can be added later if needed)

### Added Features
- **Container filtering**: Specify which container's connections to intercept
- **Proxy redirection**: Redirect intercepted connections to a proxy server
- **Bulletproof PID tracking**: Tracks all PIDs in a container's namespace

## Architecture

### eBPF Maps
- `ALLOWED_PIDS`: HashMap containing PIDs to intercept (if empty, intercepts all)
- `PROXY_CONFIG`: Configuration for proxy redirection

### Interception Flow
1. **cgroup/connect4 hook** intercepts outbound IPv4 connections
2. Checks if PID filtering is enabled (ALLOWED_PIDS map)
3. If filtering enabled, only processes connections from allowed PIDs
4. If proxy configured, modifies destination address to proxy
5. Tracks original destination for monitoring

## Usage

### Basic Commands

```bash
# Monitor all outbound connections
sudo ./test_container_proxy.sh

# Only intercept connections from a specific container
sudo ./test_container_proxy.sh --container my-app

# Redirect all connections to a proxy
sudo ./test_container_proxy.sh --proxy 127.0.0.1:8080

# Combine: filter by container AND redirect to proxy
sudo ./test_container_proxy.sh --container my-app --proxy 127.0.0.1:8080
```

### Direct Usage

```bash
# Using the userspace binary directly
sudo ./bpfhook-userspace/target/release/bpfhook \
    --container nginx \
    --proxy 127.0.0.1:8080 \
    --show-events
```

## Container Detection

The system automatically detects container PIDs by:
1. Getting the main container PID via Docker API
2. Reading all PIDs from the container's cgroup
3. Adding all PIDs to the filter map

Supported container runtimes:
- Docker (fully supported)
- Containerd (placeholder for future implementation)

## Proxy Redirection

When proxy is configured:
1. Original destination is preserved in tracking
2. Actual connection is redirected to proxy address
3. Proxy sees the connection coming from the container/host
4. Original destination info is available in logs/metrics

## Testing

### Setup Test Environment

```bash
# Start a test container
docker run -d --name test-app nginx

# Start a local proxy (e.g., using socat)
socat TCP-LISTEN:8080,fork TCP:example.com:80 &

# Run the interceptor
sudo ./test_container_proxy.sh --container test-app --proxy 127.0.0.1:8080
```

### Verify Interception

In another terminal:
```bash
# Generate traffic from the container
docker exec test-app curl http://example.com

# Traffic should be redirected to your proxy on port 8080
```

## Implementation Details

### Container Filtering
- Uses PID-based filtering at the eBPF level
- Special key (PID 0) indicates filtering is enabled
- Only connections from PIDs in the map are intercepted

### Proxy Redirection
- Modifies `sock_addr` structure in `cgroup/connect4` hook
- Changes destination IP and port before connection establishment
- Original destination stored for tracking/logging

### Performance
- LRU map for connection tracking (10,000 entries)
- Minimal overhead for non-intercepted connections
- Early return if PID not in filter list

## Limitations

1. **IPv4 only** - IPv6 support not implemented
2. **TCP only** - UDP not supported
3. **Container runtime** - Currently Docker only, containerd support pending
4. **Proxy protocol** - Standard TCP proxy, no PROXY protocol headers

## Future Enhancements

Potential improvements:
- IPv6 support via `cgroup/connect6` hook
- UDP interception
- PROXY protocol support for preserving original client info
- Containerd and CRI-O runtime support
- Per-container proxy configuration
- Dynamic filter updates without restart