//! eBPF XDP program for HTTP traffic monitoring and metrics collection.
//!
//! This program attaches to a network interface and analyzes incoming packets
//! to detect HTTP traffic, collecting metrics about request types and traffic volume.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

// Constants for packet parsing
const ETH_HEADER_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;
const MIN_IP_HEADER_LEN: usize = 20;
const MAX_IP_HEADER_LEN: usize = 60;
const MIN_TCP_HEADER_LEN: usize = 20;
const MAX_TCP_HEADER_LEN: usize = 60;

// HTTP ports to monitor
const HTTP_PORTS: [u16; 4] = [80, 8080, 8000, 3000];

/// HTTP method types for categorization
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum HttpMethod {
    Unknown = 0,
    Get = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Head = 5,
    Patch = 6,
    Trace = 7,
    Options = 8,
    Connect = 9,
}

impl HttpMethod {
    /// Get a string representation for logging
    #[inline(always)]
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Unknown => "UNKNOWN",
        }
    }
}

/// HTTP metrics structure for tracking request statistics
#[repr(C)]
#[derive(Clone, Copy)]
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

/// Map to store HTTP metrics by port
#[map]
static mut HTTP_METRICS: HashMap<u16, HttpMetrics> = HashMap::with_max_entries(1024, 0);

/// Map to store per-IP request counts
#[map]
static mut IP_REQUEST_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(10000, 0);

/// XDP entry point for packet processing
#[xdp]
pub fn bpfhook(ctx: XdpContext) -> u32 {
    match process_packet(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // Pass packet on error to avoid dropping traffic
    }
}

/// Main packet processing logic
fn process_packet(ctx: XdpContext) -> Result<u32, ()> {
    let packet_info = parse_packet(&ctx)?;

    // Only process HTTP traffic on configured ports
    if !is_http_port(packet_info.dst_port) {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check if payload contains HTTP request
    if let Some(method) = detect_http_method(packet_info.payload, packet_info.payload_end) {
        // Update metrics for this HTTP request
        update_metrics(packet_info.dst_port, method, packet_info.payload_size)?;
        update_ip_counter(packet_info.src_ip)?;

        info!(&ctx, "HTTP {} request on port {} from IP {:x}",
              method.as_str(), packet_info.dst_port, packet_info.src_ip);
    }

    Ok(xdp_action::XDP_PASS)
}

/// Packet information extracted from raw data
struct PacketInfo {
    src_ip: u32,
    dst_port: u16,
    payload: *const u8,
    payload_end: *const u8,
    payload_size: u64,
}

/// Parse packet headers and extract relevant information
fn parse_packet(ctx: &XdpContext) -> Result<PacketInfo, ()> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    unsafe {
        // Validate Ethernet header
        if !has_enough_data(data, data_end, ETH_HEADER_LEN) {
            return Err(());
        }

        // Check for IPv4
        let eth_proto = read_u16_be(data.add(12))?;
        if eth_proto != ETH_P_IP {
            return Err(());
        }

        // Parse IP header
        let ip_header = data.add(ETH_HEADER_LEN);
        if !has_enough_data(ip_header, data_end, MIN_IP_HEADER_LEN) {
            return Err(());
        }

        let ip_header_len = get_ip_header_len(ip_header)?;
        if !is_valid_header_len(ip_header_len, MIN_IP_HEADER_LEN, MAX_IP_HEADER_LEN) {
            return Err(());
        }

        // Check for TCP protocol
        let protocol = *ip_header.add(9);
        if protocol != IP_PROTO_TCP {
            return Err(());
        }

        // Extract source IP
        let src_ip = read_u32_be(ip_header.add(12))?;

        // Parse TCP header
        let tcp_start = ETH_HEADER_LEN + ip_header_len;
        let tcp_header = data.add(tcp_start);
        if !has_enough_data(tcp_header, data_end, MIN_TCP_HEADER_LEN) {
            return Err(());
        }

        let tcp_header_len = get_tcp_header_len(tcp_header)?;
        if !is_valid_header_len(tcp_header_len, MIN_TCP_HEADER_LEN, MAX_TCP_HEADER_LEN) {
            return Err(());
        }

        // Extract destination port
        let dst_port = read_u16_be(tcp_header.add(2))?;

        // Calculate payload information
        let payload_start = tcp_start + tcp_header_len;
        let payload = data.add(payload_start);

        if payload >= data_end {
            return Err(());
        }

        let payload_size = (data_end as usize - payload as usize) as u64;

        Ok(PacketInfo {
            src_ip,
            dst_port,
            payload,
            payload_end: data_end,
            payload_size,
        })
    }
}

/// Helper function to check if we have enough data
#[inline(always)]
fn has_enough_data(ptr: *const u8, end: *const u8, size: usize) -> bool {
    unsafe { ptr.add(size) <= end }
}

/// Helper function to validate header length
#[inline(always)]
fn is_valid_header_len(len: usize, min: usize, max: usize) -> bool {
    len >= min && len <= max
}

/// Check if port is an HTTP port we're monitoring
#[inline(always)]
fn is_http_port(port: u16) -> bool {
    HTTP_PORTS.contains(&port)
}

/// Read a big-endian u16 from a pointer
#[inline(always)]
unsafe fn read_u16_be(ptr: *const u8) -> Result<u16, ()> {
    Ok(u16::from_be_bytes([*ptr, *ptr.add(1)]))
}

/// Read a big-endian u32 from a pointer
#[inline(always)]
unsafe fn read_u32_be(ptr: *const u8) -> Result<u32, ()> {
    Ok(u32::from_be_bytes([
        *ptr,
        *ptr.add(1),
        *ptr.add(2),
        *ptr.add(3),
    ]))
}

/// Get IP header length from the version/IHL field
#[inline(always)]
unsafe fn get_ip_header_len(ip_header: *const u8) -> Result<usize, ()> {
    Ok(((*ip_header & 0x0F) * 4) as usize)
}

/// Get TCP header length from the data offset field
#[inline(always)]
unsafe fn get_tcp_header_len(tcp_header: *const u8) -> Result<usize, ()> {
    Ok(((*tcp_header.add(12) >> 4) * 4) as usize)
}

/// Detect if payload contains an HTTP method and return the method type
///
/// Optimized for common methods (GET, POST) while maintaining correctness
/// for all HTTP methods.
fn detect_http_method(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    unsafe {
        // Need at least 3 bytes for shortest method (GET)
        if payload.add(3) > data_end {
            return None;
        }

        // Read first byte to quickly filter non-HTTP traffic
        let b0 = *payload;

        // Use first byte to branch early - most HTTP methods start with G, P, H, D, T, C, or O
        match b0 {
            b'G' => check_get_method(payload, data_end),
            b'P' => check_p_methods(payload, data_end), // POST, PUT, PATCH
            b'H' => check_head_method(payload, data_end),
            b'D' => check_delete_method(payload, data_end),
            b'T' => check_trace_method(payload, data_end),
            b'C' => check_connect_method(payload, data_end),
            b'O' => check_options_method(payload, data_end),
            _ => None,
        }
    }
}

/// Check for GET method (most common)
#[inline(always)]
unsafe fn check_get_method(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    if payload.add(4) <= data_end &&
       *payload.add(1) == b'E' &&
       *payload.add(2) == b'T' &&
       *payload.add(3) == b' ' {
        Some(HttpMethod::Get)
    } else {
        None
    }
}

/// Check for methods starting with 'P' (POST, PUT, PATCH)
#[inline(always)]
unsafe fn check_p_methods(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    if payload.add(3) > data_end {
        return None;
    }

    let b1 = *payload.add(1);
    let b2 = *payload.add(2);

    // Check PUT (3 letters + space)
    if b1 == b'U' && b2 == b'T' {
        if payload.add(4) <= data_end && *payload.add(3) == b' ' {
            return Some(HttpMethod::Put);
        }
    }
    // Check POST (4 letters, may have space or /)
    else if b1 == b'O' && b2 == b'S' {
        if payload.add(4) <= data_end && *payload.add(3) == b'T' {
            if payload.add(5) <= data_end {
                let b4 = *payload.add(4);
                if b4 == b' ' || b4 == b'/' {
                    return Some(HttpMethod::Post);
                }
            }
        }
    }
    // Check PATCH (5 letters)
    else if b1 == b'A' && b2 == b'T' {
        if payload.add(6) <= data_end &&
           *payload.add(3) == b'C' &&
           *payload.add(4) == b'H' &&
           *payload.add(5) == b' ' {
            return Some(HttpMethod::Patch);
        }
    }

    None
}

/// Check for HEAD method
#[inline(always)]
unsafe fn check_head_method(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    if payload.add(5) <= data_end &&
       *payload.add(1) == b'E' &&
       *payload.add(2) == b'A' &&
       *payload.add(3) == b'D' &&
       *payload.add(4) == b' ' {
        Some(HttpMethod::Head)
    } else {
        None
    }
}

/// Check for DELETE method
#[inline(always)]
unsafe fn check_delete_method(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    if payload.add(7) <= data_end &&
       *payload.add(1) == b'E' &&
       *payload.add(2) == b'L' &&
       *payload.add(3) == b'E' &&
       *payload.add(4) == b'T' &&
       *payload.add(5) == b'E' &&
       *payload.add(6) == b' ' {
        Some(HttpMethod::Delete)
    } else {
        None
    }
}

/// Check for TRACE method
#[inline(always)]
unsafe fn check_trace_method(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    if payload.add(6) <= data_end &&
       *payload.add(1) == b'R' &&
       *payload.add(2) == b'A' &&
       *payload.add(3) == b'C' &&
       *payload.add(4) == b'E' &&
       *payload.add(5) == b' ' {
        Some(HttpMethod::Trace)
    } else {
        None
    }
}

/// Check for CONNECT method
#[inline(always)]
unsafe fn check_connect_method(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    if payload.add(8) <= data_end &&
       *payload.add(1) == b'O' &&
       *payload.add(2) == b'N' &&
       *payload.add(3) == b'N' &&
       *payload.add(4) == b'E' &&
       *payload.add(5) == b'C' &&
       *payload.add(6) == b'T' &&
       *payload.add(7) == b' ' {
        Some(HttpMethod::Connect)
    } else {
        None
    }
}

/// Check for OPTIONS method
#[inline(always)]
unsafe fn check_options_method(payload: *const u8, data_end: *const u8) -> Option<HttpMethod> {
    if payload.add(8) <= data_end &&
       *payload.add(1) == b'P' &&
       *payload.add(2) == b'T' &&
       *payload.add(3) == b'I' &&
       *payload.add(4) == b'O' &&
       *payload.add(5) == b'N' &&
       *payload.add(6) == b'S' &&
       *payload.add(7) == b' ' {
        Some(HttpMethod::Options)
    } else {
        None
    }
}

/// Update HTTP metrics for a given port and method
fn update_metrics(port: u16, method: HttpMethod, payload_size: u64) -> Result<(), ()> {
    unsafe {
        let timestamp = bpf_ktime_get_ns();
        let map = &mut *core::ptr::addr_of_mut!(HTTP_METRICS);

        // Try to get existing metrics for this port
        let metrics_ptr = map.get_ptr_mut(&port).ok_or(())?;

        if metrics_ptr.is_null() {
            // Create new metrics entry
            let new_metrics = create_initial_metrics(method, payload_size, timestamp);
            map.insert(&port, &new_metrics, 0).map_err(|_| ())?;
        } else {
            // Update existing metrics
            let metrics = &mut *metrics_ptr;
            metrics.total_requests += 1;
            metrics.bytes_processed += payload_size;
            metrics.last_updated = timestamp;

            // Increment the appropriate method counter
            increment_method_counter(metrics, method);
        }
    }
    Ok(())
}

/// Create initial metrics for a new port
#[inline(always)]
fn create_initial_metrics(method: HttpMethod, payload_size: u64, timestamp: u64) -> HttpMetrics {
    let mut metrics = HttpMetrics {
        total_requests: 1,
        get_requests: 0,
        post_requests: 0,
        put_requests: 0,
        delete_requests: 0,
        other_requests: 0,
        bytes_processed: payload_size,
        last_updated: timestamp,
    };

    increment_method_counter(&mut metrics, method);
    metrics
}

/// Increment the appropriate method counter in metrics
#[inline(always)]
fn increment_method_counter(metrics: &mut HttpMetrics, method: HttpMethod) {
    match method {
        HttpMethod::Get => metrics.get_requests += 1,
        HttpMethod::Post => metrics.post_requests += 1,
        HttpMethod::Put => metrics.put_requests += 1,
        HttpMethod::Delete => metrics.delete_requests += 1,
        HttpMethod::Head | HttpMethod::Patch | HttpMethod::Trace |
        HttpMethod::Options | HttpMethod::Connect | HttpMethod::Unknown => {
            metrics.other_requests += 1
        }
    }
}

/// Update the per-IP request counter
fn update_ip_counter(ip: u32) -> Result<(), ()> {
    unsafe {
        let map = &mut *core::ptr::addr_of_mut!(IP_REQUEST_COUNT);
        let count_ptr = map.get_ptr_mut(&ip).ok_or(())?;

        if count_ptr.is_null() {
            // Insert new IP with count of 1
            map.insert(&ip, &1u64, 0).map_err(|_| ())?;
        } else {
            // Increment existing count
            *count_ptr += 1;
        }
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}