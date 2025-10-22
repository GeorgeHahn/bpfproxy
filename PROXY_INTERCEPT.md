# BPFHook Proxy Interceptor

## Overview

BPFHook has been modified to focus on **incoming connection interception** with the ability to:
1. **Filter by destination container** - Intercept connections going TO specific containers
2. **Redirect to proxy** - Transparently redirect intercepted connections to a proxy server

## Key Changes

### Removed Features
- Inbound connection tracking (`inet_csk_accept` kprobe)
- IPv6 support (can be added later if needed)

### Added Features
- **Destination-based filtering**: Specify which container's IP to intercept incoming connections to
- **Proxy redirection**: Redirect intercepted connections to a proxy server
- **IP-based interception**: Intercepts based on destination IP address

## Architecture

### eBPF Maps
- `INTERCEPTED_DESTINATIONS`: HashMap containing destination IPs to intercept (and optional port filtering)
- `PROXY_CONFIG`: Configuration for proxy redirection

### Interception Flow
1. **cgroup/connect4 hook** intercepts all outbound IPv4 connections system-wide
2. Checks if destination IP matches container we want to intercept (INTERCEPTED_DESTINATIONS map)
3. If destination matches, redirects connection to proxy
4. Proxy then forwards the connection to the actual target container
5. Original destination is tracked for monitoring

## Usage

### Basic Commands

```bash
# Monitor all outbound connections
sudo ./test_container_proxy.sh

# Intercept incoming connections to 'target-server' container
sudo ./test_container_proxy.sh --container target-server

# Redirect intercepted connections to a proxy
sudo ./test_container_proxy.sh --proxy 172.17.0.4:8888

# Combine: intercept connections to container AND redirect to proxy
sudo ./test_container_proxy.sh --container target-server --proxy 172.17.0.4:8888
```

### Direct Usage

```bash
# Using the userspace binary directly
sudo ./bpfhook-userspace/target/release/bpfhook \
    --container target-server \
    --proxy 172.17.0.4:8888 \
    --show-events
```

## Container IP Detection

The system automatically detects container IP by:
1. Getting the container's IP address via Docker API
2. Adding the IP to the INTERCEPTED_DESTINATIONS map
3. All connections to that IP will be intercepted and redirected

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