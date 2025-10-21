//! Userspace component for connection monitoring with eBPF
//!
//! This program loads eBPF programs that hook connection events (connect/accept/state changes)
//! to monitor network traffic with container attribution.

use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, MapData, AsyncPerfEventArray},
    programs::{CgroupSockAddr, CgroupAttachMode, KProbe, TracePoint},
    util::online_cpus,
    Ebpf, Pod,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn, debug, trace};
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{signal, time, task};

// Connection info structure matching the eBPF side
#[derive(Debug, Clone, Copy)]
#[repr(C)]
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

// SAFETY: ConnectionInfo is a plain C struct, safe for Pod
unsafe impl Pod for ConnectionInfo {}

// Connection metrics structure matching the eBPF side
#[derive(Debug, Clone, Copy)]
#[repr(C)]
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

// SAFETY: ConnectionMetrics is a plain C struct, safe for Pod
unsafe impl Pod for ConnectionMetrics {}

// TCP state names for display
const TCP_STATES: &[&str] = &[
    "UNKNOWN",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
];

#[derive(Parser, Debug)]
#[clap(
    name = "bpfhook",
    about = "Connection monitor using eBPF with container attribution",
    version,
    author
)]
struct Args {
    /// Cgroup path to attach connect hooks (default: root cgroup v2)
    #[clap(short = 'c', long, default_value = "/sys/fs/cgroup")]
    cgroup_path: String,

    /// Interval in seconds to print metrics
    #[clap(short = 'm', long, default_value = "5")]
    metrics_interval: u64,

    /// Show container metrics separately
    #[clap(short = 's', long)]
    show_containers: bool,

    /// Show real-time connection events
    #[clap(short = 'e', long)]
    show_events: bool,

    /// Path to the eBPF program binary (can also set via EBPF_PATH env var)
    #[clap(short = 'p', long)]
    ebpf_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Resolve eBPF program path
    let ebpf_path = resolve_ebpf_path(args.ebpf_path.as_deref())?;
    info!("Loading eBPF program from: {}", ebpf_path.display());

    // Load and initialize the eBPF program
    let mut ebpf = load_ebpf_program(&ebpf_path)?;

    // Initialize eBPF logger
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Load and attach all the eBPF programs
    attach_all_programs(&mut ebpf, &args.cgroup_path)?;

    info!("eBPF programs attached successfully.");
    info!("Monitoring connections with container attribution.");
    info!("Press Ctrl-C to exit.\n");

    // Start event processing if requested (do this before getting maps to avoid borrow conflict)
    let event_handle = if args.show_events {
        Some(spawn_event_processor(&mut ebpf)?)
    } else {
        None
    };

    // Get references to the BPF maps (after mutable borrow is done)
    let connection_map = get_connection_map(&ebpf)?;
    let cgroup_metrics_map = get_cgroup_metrics_map(&ebpf)?;
    let netns_metrics_map = get_netns_metrics_map(&ebpf)?;

    // Run the monitoring loop
    run_monitoring_loop(
        connection_map,
        cgroup_metrics_map,
        netns_metrics_map,
        args.metrics_interval,
        args.show_containers,
    ).await?;

    // Clean up event processor
    if let Some(handle) = event_handle {
        handle.abort();
    }

    info!("Detaching eBPF programs...");
    Ok(())
}

/// Resolve the path to the eBPF program binary
fn resolve_ebpf_path(provided_path: Option<&Path>) -> Result<PathBuf> {
    // First try provided path
    if let Some(path) = provided_path {
        if path.exists() {
            return Ok(path.to_path_buf());
        } else {
            anyhow::bail!("eBPF program not found at: {}", path.display())
        }
    }

    // Then try environment variable
    if let Ok(env_path) = std::env::var("EBPF_PATH") {
        let path = PathBuf::from(env_path);
        if path.exists() {
            return Ok(path);
        }
    }

    // Finally try default path
    let default_path = PathBuf::from("bpfhook-ebpf/target/bpfel-unknown-none/release/bpfhook");
    if default_path.exists() {
        Ok(default_path)
    } else {
        anyhow::bail!(
            "eBPF program not found at default path: {}. \
             Please build with ./scripts/build.sh or specify path with --ebpf-path",
            default_path.display()
        )
    }
}

/// Load the eBPF program from file
fn load_ebpf_program(path: &Path) -> Result<Ebpf> {
    Ebpf::load_file(path)
        .with_context(|| format!("Failed to load eBPF program from {}", path.display()))
}

/// Attach all eBPF programs to their respective hooks
fn attach_all_programs(ebpf: &mut Ebpf, cgroup_path: &str) -> Result<()> {
    // Attach cgroup/connect4 hook
    attach_cgroup_connect4(ebpf, cgroup_path)?;

    // Attach cgroup/connect6 hook (for IPv6 support)
    attach_cgroup_connect6(ebpf, cgroup_path)?;

    // Attach tracepoint for socket state changes
    attach_sock_state_tracepoint(ebpf)?;

    // Attach kprobe for accept
    attach_accept_kprobe(ebpf)?;

    Ok(())
}

/// Attach the cgroup/connect4 program
fn attach_cgroup_connect4(ebpf: &mut Ebpf, cgroup_path: &str) -> Result<()> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut("bpfhook_connect4")
        .context("Failed to find 'bpfhook_connect4' program")?
        .try_into()
        .context("Failed to convert to CgroupSockAddr program")?;

    let cgroup = std::fs::File::open(cgroup_path)
        .with_context(|| format!("Failed to open cgroup path: {}", cgroup_path))?;

    program.load()
        .context("Failed to load cgroup/connect4 program")?;

    program.attach(cgroup, CgroupAttachMode::Single)
        .context("Failed to attach cgroup/connect4 program")?;

    info!("Attached cgroup/connect4 hook");
    Ok(())
}

/// Attach the cgroup/connect6 program
fn attach_cgroup_connect6(ebpf: &mut Ebpf, cgroup_path: &str) -> Result<()> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut("bpfhook_connect6")
        .context("Failed to find 'bpfhook_connect6' program")?
        .try_into()
        .context("Failed to convert to CgroupSockAddr program")?;

    let cgroup = std::fs::File::open(cgroup_path)
        .with_context(|| format!("Failed to open cgroup path: {}", cgroup_path))?;

    program.load()
        .context("Failed to load cgroup/connect6 program")?;

    program.attach(cgroup, CgroupAttachMode::Single)
        .context("Failed to attach cgroup/connect6 program")?;

    info!("Attached cgroup/connect6 hook");
    Ok(())
}

/// Attach the tracepoint for socket state changes
fn attach_sock_state_tracepoint(ebpf: &mut Ebpf) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut("bpfhook_sock_state")
        .context("Failed to find 'bpfhook_sock_state' program")?
        .try_into()
        .context("Failed to convert to TracePoint program")?;

    program.load()
        .context("Failed to load sock:inet_sock_set_state tracepoint")?;

    program.attach("sock", "inet_sock_set_state")
        .context("Failed to attach sock:inet_sock_set_state tracepoint")?;

    info!("Attached sock:inet_sock_set_state tracepoint");
    Ok(())
}

/// Attach the kprobe for accept
fn attach_accept_kprobe(ebpf: &mut Ebpf) -> Result<()> {
    let program: &mut KProbe = ebpf
        .program_mut("bpfhook_accept")
        .context("Failed to find 'bpfhook_accept' program")?
        .try_into()
        .context("Failed to convert to KProbe program")?;

    program.load()
        .context("Failed to load inet_csk_accept kprobe")?;

    program.attach("inet_csk_accept", 0)
        .context("Failed to attach inet_csk_accept kprobe")?;

    info!("Attached inet_csk_accept kprobe");
    Ok(())
}

/// Get the connection map
fn get_connection_map(ebpf: &Ebpf) -> Result<HashMap<&MapData, u64, ConnectionInfo>> {
    HashMap::try_from(
        ebpf.map("CONNECTION_MAP")
            .context("Failed to find CONNECTION_MAP")?
    ).context("Failed to create HashMap from CONNECTION_MAP")
}

/// Get the cgroup metrics map
fn get_cgroup_metrics_map(ebpf: &Ebpf) -> Result<HashMap<&MapData, u64, ConnectionMetrics>> {
    HashMap::try_from(
        ebpf.map("METRICS_BY_CGROUP")
            .context("Failed to find METRICS_BY_CGROUP map")?
    ).context("Failed to create HashMap from METRICS_BY_CGROUP")
}

/// Get the netns metrics map
fn get_netns_metrics_map(ebpf: &Ebpf) -> Result<HashMap<&MapData, u64, ConnectionMetrics>> {
    HashMap::try_from(
        ebpf.map("METRICS_BY_NETNS")
            .context("Failed to find METRICS_BY_NETNS map")?
    ).context("Failed to create HashMap from METRICS_BY_NETNS")
}

/// Spawn a task to process connection events
fn spawn_event_processor(ebpf: &mut Ebpf) -> Result<task::JoinHandle<()>> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        ebpf.take_map("CONNECTION_EVENTS")
            .context("Failed to find CONNECTION_EVENTS perf array")?
    )?;

    let cpus = online_cpus().map_err(|e| anyhow::anyhow!("Failed to get online CPUs: {:?}", e))?;
    let handle = task::spawn(async move {
        // Open perf buffers for all CPUs
        let mut buffers = Vec::new();
        for cpu_id in cpus {
            let buf = perf_array.open(cpu_id, None).unwrap();
            buffers.push(buf);
        }

        info!("Started connection event processor");

        let bufs = (0..buffers.len())
            .map(|_| BytesMut::with_capacity(1024))
            .collect::<Vec<_>>();

        loop {
            for (i, buf) in buffers.iter_mut().enumerate() {
                let mut bufvec = vec![bufs[i].clone()];
                match buf.read_events(&mut bufvec).await {
                    Ok(_events) => {
                        for buf in bufvec.iter() {
                            if buf.len() >= std::mem::size_of::<ConnectionInfo>() {
                                let ptr = buf.as_ptr() as *const ConnectionInfo;
                                let conn = unsafe { *ptr };
                                print_connection_event(&conn);
                            }
                        }
                    }
                    Err(e) => {
                        trace!("No events or error reading perf buffer: {}", e);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    Ok(handle)
}

/// Print a connection event
fn print_connection_event(conn: &ConnectionInfo) {
    let src_ip = Ipv4Addr::from(conn.src_addr);
    let dst_ip = Ipv4Addr::from(conn.dst_addr);
    let state_name = TCP_STATES.get(conn.state as usize).unwrap_or(&"UNKNOWN");

    let container_tag = if conn.is_container {
        " [CONTAINER]"
    } else {
        ""
    };

    debug!(
        "[{}] PID:{} {}:{}->{}:{} state={} cgroup={}{}",
        chrono::Local::now().format("%H:%M:%S%.3f"),
        conn.pid,
        src_ip, conn.src_port,
        dst_ip, conn.dst_port,
        state_name,
        conn.cgroup_id,
        container_tag
    );
}

/// Run the main monitoring loop
async fn run_monitoring_loop(
    connection_map: HashMap<&MapData, u64, ConnectionInfo>,
    cgroup_metrics: HashMap<&MapData, u64, ConnectionMetrics>,
    netns_metrics: HashMap<&MapData, u64, ConnectionMetrics>,
    interval_secs: u64,
    show_containers: bool,
) -> Result<()> {
    let mut interval = time::interval(Duration::from_secs(interval_secs));
    let mut shutdown = Box::pin(signal::ctrl_c());

    loop {
        tokio::select! {
            _ = interval.tick() => {
                display_metrics(&connection_map, &cgroup_metrics, &netns_metrics, show_containers)?;
            }
            _ = &mut shutdown => {
                info!("\nShutdown signal received. Displaying final metrics...");
                display_metrics(&connection_map, &cgroup_metrics, &netns_metrics, show_containers)?;
                break;
            }
        }
    }

    Ok(())
}

/// Display metrics in a formatted report
fn display_metrics(
    connection_map: &HashMap<&MapData, u64, ConnectionInfo>,
    cgroup_metrics: &HashMap<&MapData, u64, ConnectionMetrics>,
    netns_metrics: &HashMap<&MapData, u64, ConnectionMetrics>,
    show_containers: bool,
) -> Result<()> {
    print_report_header();

    // Display active connections
    print_active_connections(connection_map)?;

    // Display cgroup metrics
    print_cgroup_metrics(cgroup_metrics, show_containers)?;

    // Display network namespace metrics if available
    print_netns_metrics(netns_metrics)?;

    print_report_footer();
    Ok(())
}

/// Print the report header
fn print_report_header() {
    println!("\n{}", "=".repeat(80));
    println!("CONNECTION METRICS REPORT");
    println!("{}", "=".repeat(80));
}

/// Print the report footer
fn print_report_footer() {
    println!("{}", "=".repeat(80));
}

/// Print active connections
fn print_active_connections(map: &HashMap<&MapData, u64, ConnectionInfo>) -> Result<()> {
    let mut connections = Vec::new();
    let mut container_count = 0;
    let mut host_count = 0;

    for item in map.iter() {
        let (_id, conn) = item?;
        connections.push(conn);
        if conn.is_container {
            container_count += 1;
        } else {
            host_count += 1;
        }
    }

    println!("\nActive Connections:");
    println!("{}", "-".repeat(80));
    println!("  Total: {} (Host: {}, Container: {})",
             connections.len(), host_count, container_count);

    // Group by state
    let mut by_state: BTreeMap<u8, u32> = BTreeMap::new();
    for conn in &connections {
        *by_state.entry(conn.state).or_insert(0) += 1;
    }

    println!("\n  By State:");
    for (state, count) in by_state {
        let state_name = TCP_STATES.get(state as usize).unwrap_or(&"UNKNOWN");
        println!("    {:<15} {}", state_name, count);
    }

    // Show sample connections
    if !connections.is_empty() {
        println!("\n  Recent Connections (showing first 5):");
        for conn in connections.iter().take(5) {
            let src_ip = Ipv4Addr::from(conn.src_addr);
            let dst_ip = Ipv4Addr::from(conn.dst_addr);
            let state_name = TCP_STATES.get(conn.state as usize).unwrap_or(&"UNKNOWN");
            let container_tag = if conn.is_container { " [CTR]" } else { "" };

            println!("    PID:{:<8} {}:{} -> {}:{} ({}){}",
                     conn.pid, src_ip, conn.src_port,
                     dst_ip, conn.dst_port, state_name, container_tag);
        }
    }

    Ok(())
}

/// Print cgroup-based metrics
fn print_cgroup_metrics(map: &HashMap<&MapData, u64, ConnectionMetrics>, show_containers: bool) -> Result<()> {
    let mut metrics_list = Vec::new();
    let mut total = ConnectionMetrics {
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
    };

    for item in map.iter() {
        let (cgroup_id, metrics) = item?;
        metrics_list.push((cgroup_id, metrics));

        // Accumulate totals
        total.total_connections += metrics.total_connections;
        total.active_connections += metrics.active_connections;
        total.bytes_sent += metrics.bytes_sent;
        total.bytes_received += metrics.bytes_received;
    }

    println!("\nCgroup-based Metrics:");
    println!("{}", "-".repeat(80));

    if show_containers {
        println!("  Individual Cgroups:");
        for (cgroup_id, metrics) in metrics_list.iter().take(5) {
            let is_root = *cgroup_id == 1;
            let cgroup_type = if is_root { "ROOT" } else { "CONTAINER" };
            println!("\n    Cgroup {} ({}):", cgroup_id, cgroup_type);
            println!("      Total Connections:  {}", metrics.total_connections);
            println!("      Active Connections: {}", metrics.active_connections);
        }
    }

    println!("\n  Aggregate Metrics:");
    println!("    Total Connections:  {}", total.total_connections);
    println!("    Active Connections: {}", total.active_connections);
    if total.bytes_sent > 0 || total.bytes_received > 0 {
        println!("    Bytes Sent:         {}", total.bytes_sent);
        println!("    Bytes Received:     {}", total.bytes_received);
    }

    Ok(())
}

/// Print network namespace metrics
fn print_netns_metrics(map: &HashMap<&MapData, u64, ConnectionMetrics>) -> Result<()> {
    let mut has_data = false;

    for item in map.iter() {
        let (netns_cookie, _metrics) = item?;
        if netns_cookie != 0 {
            has_data = true;
            break;
        }
    }

    if !has_data {
        return Ok(());
    }

    println!("\nNetwork Namespace Metrics:");
    println!("{}", "-".repeat(80));

    let mut total_by_ns = 0u64;
    for item in map.iter() {
        let (_netns, metrics) = item?;
        total_by_ns += metrics.total_connections;
    }

    println!("  Total connections across namespaces: {}", total_by_ns);

    Ok(())
}