# BPFHook Transparent Proxy Demo Guide

## Overview

This guide demonstrates the transparent proxy interception capability of BPFHook using Docker containers.

## Architecture

```
┌─────────────────┐      Normal Path      ┌──────────────────┐
│  source-client  │ ─────────────────────> │  target-server   │
│   (generates    │                        │  (HTTP server)   │
│    traffic)     │                        │                  │
└─────────────────┘                        └──────────────────┘
        │                                            ↑
        │                                            │
        │         With BPFHook                      │
        │         Interception                      │
        │                                            │
        └──────> ┌─────────────────┐ ───────────────┘
                 │  proxy-server   │
                 │  (transparent)  │
                 └─────────────────┘
```

## Quick Demo

### Automated Demo

Run the complete demonstration:

```bash
sudo ./demo_transparent_proxy.sh
```

This script will:
1. Start all Docker containers
2. Test normal connection (without interception)
3. Start BPFHook to intercept incoming connections to `target-server`
4. Redirect intercepted traffic to the proxy
5. Show proxy logs demonstrating the interception
6. Automatically stop BPFHook at the end

### Manual Testing

#### 1. Start the containers

```bash
docker compose up -d --build
```

#### 2. Verify containers are running

```bash
docker ps
```

You should see:
- `source-client` - Source container that generates traffic
- `target-server` - Target HTTP server (intended destination)
- `proxy-server` - Transparent proxy that intercepts and forwards

#### 3. Test normal connection (no interception)

```bash
# From host
docker exec source-client curl http://target-server:8080/test

# Response comes directly from target-server
```

#### 4. Start BPFHook with interception

```bash
# Get proxy IP
PROXY_IP=$(docker inspect proxy-server -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

# Start BPFHook (intercepts incoming connections to target-server)
sudo ./test_container_proxy.sh \
    --container target-server \
    --proxy ${PROXY_IP}:8888
```

#### 5. Test intercepted connection

In another terminal:

```bash
# Watch proxy logs
docker logs -f proxy-server
```

In a third terminal:

```bash
# Make request - it will be transparently redirected to proxy
docker exec source-client curl http://target-server:8080/intercepted
```

You'll see in the proxy logs:
- Connection was intercepted
- Original destination was `target-server:8080`
- Proxy forwards the request to the real target
- Response is sent back to client

## Container Details

### source-client (Traffic Source)
- Purpose: Generate outgoing HTTP requests
- Tools: curl, wget, apache bench
- Container name: `source-client`

### target-server (Destination Server)
- Purpose: The intended destination for requests
- Port: 8080
- Container name: `target-server`
- Supports all HTTP methods

### proxy-server (Transparent Proxy)
- Purpose: Intercepts and forwards traffic transparently
- Port: 8888
- Container name: `proxy-server`
- Logs all intercepted connections
- Forwards requests to target-server

## How It Works

1. **BPFHook attaches to cgroup**: The eBPF program hooks into `cgroup/connect4` at the root cgroup
2. **Destination IP filtering**: Connections destined for the specified container's IP are intercepted
3. **Address rewriting**: When a connection tries to reach the target container, destination is changed to the proxy
4. **Transparent to both sides**: Neither client nor target container knows about the redirection
5. **Proxy forwards request**: The proxy receives the connection and forwards to the real target
6. **Response path**: Response goes target → proxy → client (reverse path of request)

## Advanced Usage

### Intercept incoming connections to specific containers

```bash
# Intercept connections TO nginx container
sudo ./test_container_proxy.sh --container nginx --proxy 172.17.0.4:8888

# Intercept connections TO redis container
sudo ./test_container_proxy.sh --container redis --proxy 172.17.0.5:6379
```

### Monitor without redirection

```bash
# Just monitor connections to target-server, no redirection
sudo ./test_container_proxy.sh --container target-server
```

### Use with external proxy

```bash
# Redirect to external proxy
sudo ./test_container_proxy.sh \
    --container my-app \
    --proxy 192.168.1.100:3128
```

## Troubleshooting

### Containers not starting

```bash
docker compose down
docker compose up -d --build
```

### Permission denied

Make sure to run with sudo:
```bash
sudo ./demo_transparent_proxy.sh
```

### Container not found

Check container name:
```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

### Proxy not receiving connections

1. Check BPFHook is running:
   ```bash
   ps aux | grep bpfhook
   ```

2. Check proxy is listening:
   ```bash
   docker logs proxy-server
   ```

3. Verify container PID filtering:
   ```bash
   docker inspect source-client | grep -i pid
   ```

## Clean Up

Stop everything:

```bash
# Stop BPFHook (Ctrl+C in its terminal)

# Stop containers
docker compose down

# Remove containers and networks
docker compose down -v
```