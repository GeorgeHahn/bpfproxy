//! Userspace component for HTTP traffic monitoring with eBPF
//!
//! This program loads an eBPF XDP program to monitor HTTP traffic,
//! collecting and displaying metrics about request types and volume.

use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, MapData},
    programs::{Xdp, XdpFlags},
    Ebpf, Pod,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{signal, time};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HttpMetrics {
    pub total_requests: u64,
    pub get_requests: u64,
    pub post_requests: u64,
    pub put_requests: u64,
    pub delete_requests: u64,
    pub other_requests: u64,
    pub bytes_processed: u64,
    pub last_updated: u64,
}

// SAFETY: HttpMetrics is a plain C struct with only u64 fields,
// making it safe to treat as Plain Old Data
unsafe impl Pod for HttpMetrics {}

#[derive(Parser, Debug)]
#[clap(
    name = "bpfhook",
    about = "HTTP traffic monitor using eBPF",
    version,
    author
)]
struct Args {
    /// Network interface to attach to
    #[clap(short, long, default_value = "lo")]
    interface: String,

    /// Interval in seconds to print metrics
    #[clap(short = 'm', long, default_value = "5")]
    metrics_interval: u64,

    /// Show top N IP addresses by request count
    #[clap(short = 't', long, default_value = "10")]
    top_ips: usize,

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

    // Load and attach the XDP program
    let program = load_xdp_program(&mut ebpf)?;
    attach_xdp_to_interface(program, &args.interface)?;

    info!(
        "XDP program attached successfully to {}. Metrics interval: {} seconds.",
        args.interface, args.metrics_interval
    );
    info!("Monitoring HTTP traffic on ports: 80, 8080, 8000, 3000");
    info!("Press Ctrl-C to exit.\n");

    // Get references to the BPF maps
    let http_metrics_map = get_http_metrics_map(&ebpf)?;
    let ip_request_count_map = get_ip_request_map(&ebpf)?;

    // Create metrics display configuration
    let display_config = MetricsDisplayConfig {
        top_ips: args.top_ips,
    };

    // Run the monitoring loop
    run_monitoring_loop(
        http_metrics_map,
        ip_request_count_map,
        args.metrics_interval,
        display_config,
    ).await?;

    info!("Detaching XDP program...");
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

/// Load the XDP program from the eBPF object
fn load_xdp_program(ebpf: &mut Ebpf) -> Result<&mut Xdp> {
    let program: &mut Xdp = ebpf
        .program_mut("bpfhook")
        .context("Failed to find 'bpfhook' XDP program")?
        .try_into()
        .context("Failed to convert program to XDP type")?;

    program.load()
        .context("Failed to load XDP program into kernel")?;

    Ok(program)
}

/// Attach the XDP program to the network interface
fn attach_xdp_to_interface(program: &mut Xdp, interface: &str) -> Result<()> {
    info!("Attaching XDP program to interface: {}", interface);
    program
        .attach(interface, XdpFlags::default())
        .with_context(|| format!("Failed to attach XDP program to interface '{}'", interface))?;
    Ok(())
}

/// Get the HTTP metrics map
fn get_http_metrics_map(ebpf: &Ebpf) -> Result<HashMap<&MapData, u16, HttpMetrics>> {
    HashMap::try_from(
        ebpf.map("HTTP_METRICS")
            .context("Failed to find HTTP_METRICS map")?
    ).context("Failed to create HashMap from HTTP_METRICS")
}

/// Get the IP request count map
fn get_ip_request_map(ebpf: &Ebpf) -> Result<HashMap<&MapData, u32, u64>> {
    HashMap::try_from(
        ebpf.map("IP_REQUEST_COUNT")
            .context("Failed to find IP_REQUEST_COUNT map")?
    ).context("Failed to create HashMap from IP_REQUEST_COUNT")
}

/// Configuration for metrics display
struct MetricsDisplayConfig {
    top_ips: usize,
}

/// Run the main monitoring loop
async fn run_monitoring_loop(
    http_metrics_map: HashMap<&MapData, u16, HttpMetrics>,
    ip_request_count_map: HashMap<&MapData, u32, u64>,
    interval_secs: u64,
    config: MetricsDisplayConfig,
) -> Result<()> {
    let mut interval = time::interval(Duration::from_secs(interval_secs));
    let mut shutdown = Box::pin(signal::ctrl_c());

    loop {
        tokio::select! {
            _ = interval.tick() => {
                display_metrics(&http_metrics_map, &ip_request_count_map, &config)?;
            }
            _ = &mut shutdown => {
                info!("\nShutdown signal received. Displaying final metrics...");
                display_metrics(&http_metrics_map, &ip_request_count_map, &config)?;
                break;
            }
        }
    }

    Ok(())
}

/// Display metrics in a formatted report
fn display_metrics(
    http_metrics_map: &HashMap<&MapData, u16, HttpMetrics>,
    ip_request_count_map: &HashMap<&MapData, u32, u64>,
    config: &MetricsDisplayConfig,
) -> Result<()> {
    let port_metrics = collect_port_metrics(http_metrics_map)?;
    let ip_stats = collect_ip_statistics(ip_request_count_map)?;

    print_report_header();
    print_port_metrics(&port_metrics);
    print_aggregate_metrics(&port_metrics);
    print_top_ips(&ip_stats, config.top_ips);

    if port_metrics.is_empty() && ip_stats.is_empty() {
        print_no_data_message();
    }

    print_report_footer();
    Ok(())
}

/// Collected metrics for all ports
struct PortMetricsCollection {
    by_port: Vec<(u16, HttpMetrics)>,
    total: HttpMetrics,
}

impl PortMetricsCollection {
    fn is_empty(&self) -> bool {
        self.total.total_requests == 0
    }
}

/// Collect metrics from all monitored ports
fn collect_port_metrics(
    map: &HashMap<&MapData, u16, HttpMetrics>
) -> Result<PortMetricsCollection> {
    let mut by_port = Vec::new();
    let mut total = HttpMetrics {
        total_requests: 0,
        get_requests: 0,
        post_requests: 0,
        put_requests: 0,
        delete_requests: 0,
        other_requests: 0,
        bytes_processed: 0,
        last_updated: 0,
    };

    for item in map.iter() {
        let (port, metrics) = item?;
        by_port.push((port, metrics));

        // Accumulate totals
        total.total_requests += metrics.total_requests;
        total.get_requests += metrics.get_requests;
        total.post_requests += metrics.post_requests;
        total.put_requests += metrics.put_requests;
        total.delete_requests += metrics.delete_requests;
        total.other_requests += metrics.other_requests;
        total.bytes_processed += metrics.bytes_processed;
    }

    // Sort by port number
    by_port.sort_by_key(|&(port, _)| port);

    Ok(PortMetricsCollection { by_port, total })
}

/// Collect IP request statistics
fn collect_ip_statistics(
    map: &HashMap<&MapData, u32, u64>
) -> Result<Vec<(Ipv4Addr, u64)>> {
    let mut ip_counts = Vec::new();

    for item in map.iter() {
        let (ip_u32, count) = item?;
        let ip = Ipv4Addr::from(ip_u32);
        ip_counts.push((ip, count));
    }

    // Sort by count (descending)
    ip_counts.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(ip_counts)
}

/// Print the report header
fn print_report_header() {
    println!("\n{}", "=".repeat(80));
    println!("HTTP METRICS REPORT");
    println!("{}", "=".repeat(80));
}

/// Print the report footer
fn print_report_footer() {
    println!("\n{}", "=".repeat(80));
}

/// Print metrics for individual ports
fn print_port_metrics(metrics: &PortMetricsCollection) {
    if metrics.by_port.is_empty() {
        return;
    }

    println!("\nPort-based HTTP Metrics:");
    println!("{}", "-".repeat(80));

    for (port, m) in &metrics.by_port {
        println!("\n  Port {}:", port);
        println!("    Total Requests:  {}", m.total_requests);
        println!("    GET Requests:    {}", m.get_requests);
        println!("    POST Requests:   {}", m.post_requests);
        println!("    PUT Requests:    {}", m.put_requests);
        println!("    DELETE Requests: {}", m.delete_requests);
        println!("    Other Requests:  {}", m.other_requests);
        println!(
            "    Bytes Processed: {} ({:.2} MB)",
            m.bytes_processed,
            bytes_to_mb(m.bytes_processed)
        );
    }
}

/// Print aggregate metrics across all ports
fn print_aggregate_metrics(metrics: &PortMetricsCollection) {
    if metrics.is_empty() {
        return;
    }

    let total = &metrics.total;

    println!("\nTotal Across All Ports:");
    println!("{}", "-".repeat(80));
    println!("  Total Requests:  {}", total.total_requests);

    // Print method breakdown with percentages
    print_method_stat("GET", total.get_requests, total.total_requests);
    print_method_stat("POST", total.post_requests, total.total_requests);
    print_method_stat("PUT", total.put_requests, total.total_requests);
    print_method_stat("DELETE", total.delete_requests, total.total_requests);
    print_method_stat("Other", total.other_requests, total.total_requests);

    println!(
        "  Total Bytes:     {} ({:.2} MB)",
        total.bytes_processed,
        bytes_to_mb(total.bytes_processed)
    );
}

/// Print a single method statistic with percentage
fn print_method_stat(name: &str, count: u64, total: u64) {
    let percentage = if total > 0 {
        (count as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "  {:<16} {} ({:.1}%)",
        format!("{} Requests:", name),
        count,
        percentage
    );
}

/// Print top IPs by request count
fn print_top_ips(ip_stats: &[(Ipv4Addr, u64)], top_ips: usize) {
    if ip_stats.is_empty() {
        return;
    }

    println!("\nTop {} IP Addresses by Request Count:", top_ips);
    println!("{}", "-".repeat(80));
    println!("  {:<20} {:<15} {:<20}", "IP Address", "Requests", "Percentage");
    println!("  {:<20} {:<15} {:<20}", "-".repeat(18), "-".repeat(13), "-".repeat(18));

    let total_requests: u64 = ip_stats.iter().map(|(_, count)| count).sum();

    for (ip, count) in ip_stats.iter().take(top_ips) {
        let percentage = (*count as f64 / total_requests as f64) * 100.0;
        println!("  {:<20} {:<15} {:.1}%", ip, count, percentage);
    }

    if ip_stats.len() > top_ips {
        println!("  ... and {} more IP addresses", ip_stats.len() - top_ips);
    }
}

/// Print message when no data is available
fn print_no_data_message() {
    println!("\n  No HTTP requests detected yet.");
    println!("  Make sure HTTP traffic is being sent to the monitored interface.");
}

/// Convert bytes to megabytes
fn bytes_to_mb(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}