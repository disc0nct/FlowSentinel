use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub query: String,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolStats {
    pub tcp_bytes: u64,
    pub udp_bytes: u64,
    pub icmp_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessMetrics {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub cmdline: Option<String>,
    pub uid: u32,
    pub container_id: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_per_sec: f64,
    pub packets_per_sec: f64,
    pub connection_count: usize,
    pub protocol_stats: ProtocolStats,
    #[serde(skip)]
    pub connections: Vec<ConnectionInfo>,
    #[serde(skip)]
    pub dns_queries: Vec<DnsQuery>,
    #[serde(skip)]
    pub last_seen: std::time::Instant,
    
    // Internal fields for rate calculation
    #[serde(skip)]
    pub prev_bytes_in: u64,
    #[serde(skip)]
    pub prev_bytes_out: u64,
    #[serde(skip)]
    pub prev_packets_in: u64,
    #[serde(skip)]
    pub prev_packets_out: u64,
    #[serde(skip)]
    pub last_rate_update: Option<std::time::Instant>,
    
    #[serde(skip)]
    pub history: std::collections::VecDeque<u64>,
    
    #[serde(skip)]
    pub is_recording: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub remote_domain: Option<String>,
    pub protocol: String,
    pub state: String,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
    pub rtt_ms: Option<u32>,
    pub inode: u64,
    pub country: Option<String>,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone)]
pub struct SocketStats {
    pub inode: u64,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub packets_sent: u64,
    pub uid: u32,
}

impl Default for ProcessMetrics {
    fn default() -> Self {
        Self {
            pid: 0,
            ppid: None,
            name: String::new(),
            cmdline: None,
            uid: 0,
            container_id: None,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            bytes_per_sec: 0.0,
            packets_per_sec: 0.0,
            connection_count: 0,
            protocol_stats: ProtocolStats::default(),
            connections: Vec::new(),
            dns_queries: Vec::new(),
            last_seen: std::time::Instant::now(),
            prev_bytes_in: 0,
            prev_bytes_out: 0,
            prev_packets_in: 0,
            prev_packets_out: 0,
            last_rate_update: None,
            history: std::collections::VecDeque::new(),
            is_recording: false,
        }
    }
}
