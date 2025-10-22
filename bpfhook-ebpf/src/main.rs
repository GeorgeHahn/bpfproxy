#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_CURRENT_CPU,
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{cgroup_sock_addr, kprobe, kretprobe, map, tracepoint},
    maps::{HashMap, LruHashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext, SockAddrContext, TracePointContext},
    EbpfContext,
};

// Connection tracking structures
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub tid: u32,
    pub cgroup_id: u64,
    pub netns_cookie: u64,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub state: u8,
    pub timestamp: u64,
    pub is_container: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectionMetrics {
    pub total_connections: u64,
    pub active_connections: u64,
    pub last_updated: u64,
}

// Proxy configuration for redirection
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProxyConfig {
    pub proxy_addr: u32,  // IPv4 address of proxy
    pub proxy_port: u16,  // Port of proxy
    pub enabled: bool,    // Whether redirection is enabled
}

// Socket state values from Linux kernel
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
#[allow(dead_code)]
const TCP_SYN_RECV: u8 = 3;
#[allow(dead_code)]
const TCP_FIN_WAIT1: u8 = 4;
#[allow(dead_code)]
const TCP_FIN_WAIT2: u8 = 5;
#[allow(dead_code)]
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE: u8 = 7;
#[allow(dead_code)]
const TCP_CLOSE_WAIT: u8 = 8;
#[allow(dead_code)]
const TCP_LAST_ACK: u8 = 9;
#[allow(dead_code)]
const TCP_LISTEN: u8 = 10;
#[allow(dead_code)]
const TCP_CLOSING: u8 = 11;

// Address families
const AF_INET: u16 = 2;
#[allow(dead_code)]
const AF_INET6: u16 = 10;

// Maps for tracking connections and metrics
#[map]
static CONNECTION_MAP: LruHashMap<u64, ConnectionInfo> = LruHashMap::with_max_entries(10000, 0);

#[map]
static METRICS_BY_CGROUP: HashMap<u64, ConnectionMetrics> = HashMap::with_max_entries(1024, 0);

#[map]
static METRICS_BY_NETNS: HashMap<u64, ConnectionMetrics> = HashMap::with_max_entries(1024, 0);

#[map]
static CONNECTION_EVENTS: PerfEventArray<ConnectionInfo> = PerfEventArray::new(0);

// Destination filtering map - connections to these IPs will be intercepted
// Key: IPv4 address (u32), Value: Port (u16) - use 0 for any port
#[map]
static INTERCEPTED_DESTINATIONS: HashMap<u32, u16> = HashMap::with_max_entries(1024, 0);

// Proxy configuration map - stores proxy address to redirect to
#[map]
static PROXY_CONFIG: HashMap<u32, ProxyConfig> = HashMap::with_max_entries(1, 0);

// Generate unique connection ID from 4-tuple
#[inline(always)]
fn gen_conn_id(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16) -> u64 {
    ((src_addr as u64) << 32) | ((dst_addr as u64) << 16) | ((src_port as u64) << 8) | (dst_port as u64)
}

// Check if this is a container based on cgroup and network namespace
#[inline(always)]
fn is_container_connection(cgroup_id: u64, netns_cookie: u64) -> bool {
    // Improved container detection heuristic:
    // 1. Root cgroup (ID 1) is definitely not a container
    // 2. Very high cgroup IDs (> 4096) are likely containers (systemd uses lower IDs)
    // 3. Non-zero network namespace cookie indicates a custom namespace (likely container)
    //
    // Note: This is still a heuristic. For production use, consider:
    // - Reading cgroup path and checking for /docker/, /kubepods/, /containerd/, etc.
    // - Maintaining a map of known container cgroup IDs
    // - Using additional signals like mount namespace, PID namespace, etc.

    if cgroup_id == 1 {
        return false;  // Root cgroup is definitely not a container
    }

    // High cgroup IDs or custom network namespaces likely indicate containers
    cgroup_id > 4096 || netns_cookie != 0
}


// Hook for outbound IPv4 connections (cgroup/connect4)
#[cgroup_sock_addr(connect4)]
pub fn bpfhook_connect4(ctx: SockAddrContext) -> i32 {
    match try_bpfhook_connect4(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_bpfhook_connect4(ctx: SockAddrContext) -> Result<i32, i64> {
    let sock_addr = unsafe { &mut *ctx.sock_addr };

    // Only handle IPv4
    if sock_addr.family != (AF_INET as u32) {
        return Ok(1);
    }

    // Get connection info
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Read destination address from context first to check if we should intercept
    // sock_addr.user_ip4 is in network byte order (big-endian)
    let orig_dst_addr = sock_addr.user_ip4;
    let orig_dst_port = sock_addr.user_port as u16;

    // Create a connection event to see what IP we're checking
    let debug_conn = ConnectionInfo {
        pid,
        tid,
        cgroup_id,
        netns_cookie: 0,
        src_addr: 0,
        dst_addr: orig_dst_addr,  // This will show us what IP we're seeing
        src_port: 0,
        dst_port: orig_dst_port,
        protocol: 6,
        state: 99,  // Use state 99 as debug marker
        timestamp: unsafe { bpf_ktime_get_ns() },
        is_container: true,
    };

    // Send debug event to userspace
    CONNECTION_EVENTS.output(&ctx, &debug_conn, BPF_F_CURRENT_CPU as u32);

    // Check if destination filtering is enabled by looking for destinations in the map
    // We use a special key (0) to indicate if filtering is enabled
    unsafe {
        let filter_key = 0u32;
        let filtering_enabled = INTERCEPTED_DESTINATIONS.get(&filter_key).is_some();

        if filtering_enabled {
            // Debug: Log what IP we're checking
            // For debugging: convert to see the actual IP
            let _ip_bytes = orig_dst_addr.to_be_bytes();

            // Check if this destination IP is one we want to intercept
            if let Some(port) = INTERCEPTED_DESTINATIONS.get(&orig_dst_addr) {
                // If port is 0, intercept connections to any port on this IP
                // Otherwise, only intercept if the port matches
                if *port != 0 && *port != orig_dst_port {
                    return Ok(1); // Port doesn't match, don't intercept
                }
                // Destination matched, continue with interception
            } else {
                return Ok(1); // Destination not in our intercept list
            }
        }
    }

    // For cgroup/connect hooks, we don't have direct socket access
    // So we'll set netns_cookie to 0 and rely on cgroup_id for container attribution
    let netns_cookie = 0u64;

    // Check if proxy redirection is enabled
    unsafe {
        let key = 0u32;
        if let Some(proxy) = PROXY_CONFIG.get(&key) {
            if proxy.enabled {
                // Redirect to proxy - modify the destination address
                // proxy_addr is already in network byte order
                sock_addr.user_ip4 = proxy.proxy_addr;
                sock_addr.user_port = proxy.proxy_port as u32;
            }
        }
    }

    // For connect, source port is usually assigned by kernel, we'll track in state change
    let conn_info = ConnectionInfo {
        pid,
        tid,
        cgroup_id,
        netns_cookie,
        src_addr: 0, // Will be filled during state change
        dst_addr: orig_dst_addr, // Store original destination for tracking
        src_port: 0, // Will be filled during state change
        dst_port: orig_dst_port, // Store original port for tracking
        protocol: 6, // TCP
        state: TCP_SYN_SENT,
        timestamp: unsafe { bpf_ktime_get_ns() },
        is_container: is_container_connection(cgroup_id, netns_cookie),
    };

    // Store connection info
    let conn_id = gen_conn_id(0, orig_dst_addr, 0, orig_dst_port);
    CONNECTION_MAP.insert(&conn_id, &conn_info, 0)?;

    // Send event to userspace
    CONNECTION_EVENTS.output(&ctx, &conn_info, BPF_F_CURRENT_CPU as u32);

    // Update metrics
    update_metrics(cgroup_id, netns_cookie, true, false);

    Ok(1)
}

// IPv6 support is not currently implemented
// TODO: Add IPv6 support by implementing cgroup/connect6 hook
// This would require handling IPv6 addresses (128-bit) and updating
// data structures to support both IPv4 and IPv6

// Map to store socket addresses being accepted
#[map]
static ACCEPTING_SOCKS: HashMap<u64, ConnectionInfo> = HashMap::with_max_entries(1024, 0);

// Kprobe for accept4 syscall - this captures incoming connections
#[kprobe]
pub fn bpfhook_accept4(ctx: ProbeContext) -> u32 {
    match try_bpfhook_accept4(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_bpfhook_accept4(_ctx: ProbeContext) -> Result<u32, i64> {
    // Get process info
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Store info about this accept call for processing in kretprobe
    let conn_info = ConnectionInfo {
        pid,
        tid,
        cgroup_id,
        netns_cookie: 0,
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
        protocol: 6, // TCP
        state: TCP_LISTEN,  // Mark as listening/accepting
        timestamp: unsafe { bpf_ktime_get_ns() },
        is_container: is_container_connection(cgroup_id, 0),
    };

    // Store using pid_tgid as key for retrieval in kretprobe
    ACCEPTING_SOCKS.insert(&pid_tgid, &conn_info, 0)?;

    Ok(0)
}

// Kretprobe for accept4 - this is called after the accept completes
#[kretprobe]
pub fn bpfhook_accept4_ret(ctx: RetProbeContext) -> u32 {
    match try_bpfhook_accept4_ret(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_bpfhook_accept4_ret(ctx: RetProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Get the stored connection info from kprobe
    let conn_info = unsafe {
        match ACCEPTING_SOCKS.get(&pid_tgid) {
            Some(info) => *info,
            None => return Ok(0),
        }
    };

    // Clean up the temporary storage
    unsafe {
        ACCEPTING_SOCKS.remove(&pid_tgid)?;
    }

    // Check if the accept was successful (return value > 0)
    // The ret() method returns an Option<T> where T is the return type
    let ret_val: Option<i64> = ctx.ret();
    if ret_val.is_none() || ret_val.unwrap() <= 0 {
        return Ok(0); // Accept failed (returned 0 or negative)
    }

    // Check if we're monitoring this container
    if conn_info.is_container {
        // Log that an incoming connection was accepted
        let intercept_info = ConnectionInfo {
            pid: conn_info.pid,
            tid: conn_info.tid,
            cgroup_id: conn_info.cgroup_id,
            netns_cookie: 0,
            src_addr: 0,  // Will be filled by getpeername if needed
            dst_addr: 0,  // Will be filled by getsockname if needed
            src_port: 0,
            dst_port: 8080,  // Default port, will be filled properly
            protocol: 6, // TCP
            state: 98,  // Mark as intercepted incoming connection
            timestamp: unsafe { bpf_ktime_get_ns() },
            is_container: true,
        };

        // Send event to userspace
        CONNECTION_EVENTS.output(&ctx, &intercept_info, BPF_F_CURRENT_CPU as u32);

        // Update metrics
        update_metrics(conn_info.cgroup_id, 0, false, true);
    }

    Ok(0)
}

// Also hook accept (older syscall)
#[kprobe]
pub fn bpfhook_accept(ctx: ProbeContext) -> u32 {
    match try_bpfhook_accept4(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn bpfhook_accept_ret(ctx: RetProbeContext) -> u32 {
    match try_bpfhook_accept4_ret(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

// Tracepoint field offsets for sock:inet_sock_set_state
// These offsets are for the standard kernel tracepoint structure:
// struct trace_event_raw_inet_sock_set_state {
//     struct trace_entry ent;  // 8 bytes
//     int oldstate;            // 4 bytes at offset 8
//     int newstate;            // 4 bytes at offset 12
//     __u16 sport;             // 2 bytes at offset 16
//     __u16 dport;             // 2 bytes at offset 18
//     __u16 family;            // 2 bytes at offset 20
//     __u8 protocol;           // 1 byte at offset 22
//     // padding              // 1 byte at offset 23
//     __u8 saddr[4];          // 4 bytes at offset 24 (IPv4) or 16 bytes (IPv6)
//     __u8 daddr[4];          // 4 bytes at offset 40 (IPv4) or 16 bytes (IPv6)
// }
#[allow(dead_code)]
const TRACEPOINT_OFFSET_OLDSTATE: usize = 8;
const TRACEPOINT_OFFSET_NEWSTATE: usize = 12;
const TRACEPOINT_OFFSET_SPORT: usize = 16;
const TRACEPOINT_OFFSET_DPORT: usize = 18;
const TRACEPOINT_OFFSET_FAMILY: usize = 20;
#[allow(dead_code)]
const TRACEPOINT_OFFSET_PROTOCOL: usize = 22;
const TRACEPOINT_OFFSET_SADDR_IPV4: usize = 24;
const TRACEPOINT_OFFSET_DADDR_IPV4: usize = 40;

// Helper macro for safe kernel reads with validation
macro_rules! read_kernel_field {
    ($ctx:expr, $offset:expr, $type:ty) => {
        unsafe {
            let ptr = $ctx.as_ptr().add($offset) as *const $type;
            bpf_probe_read_kernel(ptr).unwrap_or(0 as $type)
        }
    };
}

// Tracepoint for socket state changes
#[tracepoint]
pub fn bpfhook_sock_state(ctx: TracePointContext) -> u32 {
    match try_bpfhook_sock_state(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_bpfhook_sock_state(ctx: TracePointContext) -> Result<u32, i64> {
    // The tracepoint args structure for sock:inet_sock_set_state
    // Read fields using defined offsets for better maintainability

    // Read the new state
    let newstate: i32 = read_kernel_field!(ctx, TRACEPOINT_OFFSET_NEWSTATE, i32);

    // Validate state is within expected range
    if newstate < 0 || newstate > 11 {
        return Ok(0); // Invalid state, skip
    }

    // Read source and dest ports
    let sport: u16 = read_kernel_field!(ctx, TRACEPOINT_OFFSET_SPORT, u16);
    let dport: u16 = read_kernel_field!(ctx, TRACEPOINT_OFFSET_DPORT, u16);

    // Read family
    let family: u16 = read_kernel_field!(ctx, TRACEPOINT_OFFSET_FAMILY, u16);

    // Only handle IPv4 TCP
    if family != AF_INET {
        return Ok(0);
    }

    // Read source and dest addresses for IPv4
    let saddr: u32 = read_kernel_field!(ctx, TRACEPOINT_OFFSET_SADDR_IPV4, u32);
    let daddr: u32 = read_kernel_field!(ctx, TRACEPOINT_OFFSET_DADDR_IPV4, u32);

    // Get process and container info
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let netns_cookie = 0; // Would need socket pointer to get this

    let conn_info = ConnectionInfo {
        pid,
        tid,
        cgroup_id,
        netns_cookie,
        src_addr: saddr,
        dst_addr: daddr,
        src_port: sport,
        dst_port: dport,
        protocol: 6, // TCP
        state: newstate as u8,
        timestamp: unsafe { bpf_ktime_get_ns() },
        is_container: is_container_connection(cgroup_id, netns_cookie),
    };

    // Store/update connection info
    let conn_id = gen_conn_id(saddr, daddr, sport, dport);
    CONNECTION_MAP.insert(&conn_id, &conn_info, 0)?;

    // Send state change event to userspace
    CONNECTION_EVENTS.output(&ctx, &conn_info, BPF_F_CURRENT_CPU as u32);

    // Track metrics for established and closed connections
    if newstate == TCP_ESTABLISHED as i32 {
        update_metrics(cgroup_id, netns_cookie, false, true);
    } else if newstate == TCP_CLOSE as i32 {
        update_metrics(cgroup_id, netns_cookie, false, false);
    }

    Ok(0)
}


// Helper function to update metrics
fn update_metrics(cgroup_id: u64, netns_cookie: u64, is_connect: bool, is_established: bool) {
    let timestamp = unsafe { bpf_ktime_get_ns() };

    // Update cgroup-based metrics
    unsafe {
        let mut metrics = METRICS_BY_CGROUP.get(&cgroup_id).copied().unwrap_or(ConnectionMetrics {
            total_connections: 0,
            active_connections: 0,
            last_updated: 0,
        });

        if is_connect {
            metrics.total_connections += 1;
        }
        if is_established {
            metrics.active_connections += 1;
        }
        metrics.last_updated = timestamp;

        let _ = METRICS_BY_CGROUP.insert(&cgroup_id, &metrics, 0);
    }

    // Update netns-based metrics if available
    if netns_cookie != 0 {
        unsafe {
            let mut metrics = METRICS_BY_NETNS.get(&netns_cookie).copied().unwrap_or(ConnectionMetrics {
                total_connections: 0,
                active_connections: 0,
                last_updated: 0,
            });

            if is_connect {
                metrics.total_connections += 1;
            }
            if is_established {
                metrics.active_connections += 1;
            }
            metrics.last_updated = timestamp;

            let _ = METRICS_BY_NETNS.insert(&netns_cookie, &metrics, 0);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}