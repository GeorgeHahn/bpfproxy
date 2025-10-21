#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_CURRENT_CPU,
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{cgroup_sock_addr, kprobe, map, tracepoint},
    maps::{HashMap, LruHashMap, PerfEventArray},
    programs::{SockAddrContext, ProbeContext, TracePointContext},
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
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub http_requests: u64,
    pub get_requests: u64,
    pub post_requests: u64,
    pub put_requests: u64,
    pub delete_requests: u64,
    pub other_requests: u64,
    pub last_updated: u64,
}

// Socket state values from Linux kernel
const TCP_ESTABLISHED: u8 = 1;
const TCP_SYN_SENT: u8 = 2;
const TCP_SYN_RECV: u8 = 3;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE: u8 = 7;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_LAST_ACK: u8 = 9;
const TCP_LISTEN: u8 = 10;
const TCP_CLOSING: u8 = 11;

// Address families
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// Maps for tracking connections and metrics
#[map]
static mut CONNECTION_MAP: LruHashMap<u64, ConnectionInfo> = LruHashMap::with_max_entries(10000, 0);

#[map]
static mut METRICS_BY_CGROUP: HashMap<u64, ConnectionMetrics> = HashMap::with_max_entries(1024, 0);

#[map]
static mut METRICS_BY_NETNS: HashMap<u64, ConnectionMetrics> = HashMap::with_max_entries(1024, 0);

#[map]
static mut CONNECTION_EVENTS: PerfEventArray<ConnectionInfo> = PerfEventArray::new(0);

// Generate unique connection ID from 4-tuple
#[inline(always)]
fn gen_conn_id(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16) -> u64 {
    ((src_addr as u64) << 32) | ((dst_addr as u64) << 16) | ((src_port as u64) << 8) | (dst_port as u64)
}

// Check if this is a container based on cgroup path or namespace
#[inline(always)]
fn is_container_connection(cgroup_id: u64, netns_cookie: u64) -> bool {
    // Simple heuristic: non-root cgroup or non-default netns indicates container
    // In production, you'd want more sophisticated checks
    cgroup_id != 1 || netns_cookie != 0
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
    let sock_addr = unsafe { &*ctx.sock_addr };

    // Only handle IPv4
    if sock_addr.family != (AF_INET as u32) {
        return Ok(1);
    }

    // Get connection info
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // For cgroup/connect hooks, we don't have direct socket access
    // So we'll set netns_cookie to 0 and rely on cgroup_id for container attribution
    let netns_cookie = 0u64;

    // Read destination address from context
    let dst_addr = u32::from_be(sock_addr.user_ip4);
    let dst_port = u16::from_be(sock_addr.user_port as u16);

    // For connect, source port is usually assigned by kernel, we'll track in state change
    let conn_info = ConnectionInfo {
        pid,
        tid,
        cgroup_id,
        netns_cookie,
        src_addr: 0, // Will be filled during state change
        dst_addr,
        src_port: 0, // Will be filled during state change
        dst_port,
        protocol: 6, // TCP
        state: TCP_SYN_SENT,
        timestamp: unsafe { bpf_ktime_get_ns() },
        is_container: is_container_connection(cgroup_id, netns_cookie),
    };

    // Store connection info
    let conn_id = gen_conn_id(0, dst_addr, 0, dst_port);
    unsafe {
        CONNECTION_MAP.insert(&conn_id, &conn_info, 0)?;
    }

    // Send event to userspace
    unsafe {
        CONNECTION_EVENTS.output(&ctx, &conn_info, BPF_F_CURRENT_CPU as u32);
    }

    // Update metrics
    update_metrics(cgroup_id, netns_cookie, true, false);

    Ok(1)
}

// Hook for outbound IPv6 connections (cgroup/connect6)
#[cgroup_sock_addr(connect6)]
pub fn bpfhook_connect6(_ctx: SockAddrContext) -> i32 {
    // For now, we'll focus on IPv4. IPv6 can be added similarly
    1
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
    // Contains: oldstate, newstate, sport, dport, family, protocol, saddr[], daddr[]

    // Read the new state (offset 8 bytes from start of args)
    let newstate: i32 = unsafe {
        let ptr = ctx.as_ptr().add(8) as *const i32;
        bpf_probe_read_kernel(ptr).unwrap_or(0)
    };

    // Read source and dest ports (offsets 16 and 18)
    let sport: u16 = unsafe {
        let sport_ptr = ctx.as_ptr().add(16) as *const u16;
        bpf_probe_read_kernel(sport_ptr).unwrap_or(0)
    };
    let dport: u16 = unsafe {
        let dport_ptr = ctx.as_ptr().add(18) as *const u16;
        bpf_probe_read_kernel(dport_ptr).unwrap_or(0)
    };

    // Read family (offset 20)
    let family: u16 = unsafe {
        let family_ptr = ctx.as_ptr().add(20) as *const u16;
        bpf_probe_read_kernel(family_ptr).unwrap_or(0)
    };

    // Only handle IPv4 TCP
    if family != AF_INET {
        return Ok(0);
    }

    // Read source and dest addresses for IPv4 (offsets 24 and 40)
    let saddr: u32 = unsafe {
        let saddr_ptr = ctx.as_ptr().add(24) as *const u32;
        bpf_probe_read_kernel(saddr_ptr).unwrap_or(0)
    };
    let daddr: u32 = unsafe {
        let daddr_ptr = ctx.as_ptr().add(40) as *const u32;
        bpf_probe_read_kernel(daddr_ptr).unwrap_or(0)
    };

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
    unsafe {
        CONNECTION_MAP.insert(&conn_id, &conn_info, 0)?;
    }

    // Send state change event to userspace
    unsafe {
        CONNECTION_EVENTS.output(&ctx, &conn_info, BPF_F_CURRENT_CPU as u32);
    }

    // Track metrics for established and closed connections
    if newstate == TCP_ESTABLISHED as i32 {
        update_metrics(cgroup_id, netns_cookie, false, true);
    } else if newstate == TCP_CLOSE as i32 {
        update_metrics(cgroup_id, netns_cookie, false, false);
    }

    Ok(0)
}

// Kprobe for inbound connections (inet_csk_accept)
#[kprobe]
pub fn bpfhook_accept(ctx: ProbeContext) -> u32 {
    match try_bpfhook_accept(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_bpfhook_accept(ctx: ProbeContext) -> Result<u32, i64> {
    // Get process and container info
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // For accept, we track that this process accepted a connection
    // The actual connection details will come from state changes
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
        state: TCP_ESTABLISHED,
        timestamp: unsafe { bpf_ktime_get_ns() },
        is_container: is_container_connection(cgroup_id, 0),
    };

    // Send accept event to userspace
    unsafe {
        CONNECTION_EVENTS.output(&ctx, &conn_info, BPF_F_CURRENT_CPU as u32);
    }

    // Update metrics for inbound connection
    update_metrics(cgroup_id, 0, false, true);

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
            bytes_sent: 0,
            bytes_received: 0,
            http_requests: 0,
            get_requests: 0,
            post_requests: 0,
            put_requests: 0,
            delete_requests: 0,
            other_requests: 0,
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
                bytes_sent: 0,
                bytes_received: 0,
                http_requests: 0,
                get_requests: 0,
                post_requests: 0,
                put_requests: 0,
                delete_requests: 0,
                other_requests: 0,
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