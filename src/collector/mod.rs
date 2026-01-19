pub mod netlink;
pub mod proc;
mod types;

pub use types::*;

use crate::store::Store;
use crate::geoip::GeoResolver;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, warn};

pub struct Collector {
    store: Arc<RwLock<Store>>,
    socket_to_pid: HashMap<u64, u32>,
    prev_socket_stats: HashMap<u64, SocketStats>,
    geo_resolver: Arc<GeoResolver>,
}

impl Collector {
    pub fn new(store: Arc<RwLock<Store>>, geo_resolver: Arc<GeoResolver>) -> Self {
        Self {
            store,
            socket_to_pid: HashMap::new(),
            prev_socket_stats: HashMap::new(),
            geo_resolver,
        }
    }

    pub async fn run(&mut self, interval_ms: u64) {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(interval_ms));

        loop {
            interval.tick().await;

            if let Err(e) = self.collect_once().await {
                warn!("Collection error: {}", e);
            }
        }
    }

    async fn collect_once(&mut self) -> anyhow::Result<()> {
        // Step 1: Build socket inode -> PID mapping from /proc
        self.socket_to_pid = proc::build_socket_to_pid_map()?;

        // Step 2: Get socket stats from netlink (inet_diag) and /proc/net
        let current_stats = self.collect_socket_stats()?;

        // Step 3: Calculate deltas and update store
        let now = std::time::Instant::now();
        let mut process_metrics: HashMap<u32, ProcessMetrics> = HashMap::new();

        for (inode, stats) in &current_stats {
            let pid = self.socket_to_pid.get(inode).copied();

            if let Some(pid) = pid {
                let entry = process_metrics.entry(pid).or_insert_with(|| {
                    let (name, uid, ppid, cmdline, container_id) = proc::get_process_info(pid).unwrap_or_else(|| {
                        (format!("pid:{}", pid), 0, None, None, None)
                    });
                    ProcessMetrics {
                        pid,
                        ppid,
                        name,
                        cmdline,
                        uid,
                        container_id,
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
                        last_seen: now,
                        prev_bytes_in: 0,
                        prev_bytes_out: 0,
                        prev_packets_in: 0,
                        prev_packets_out: 0,
                        last_rate_update: None,
                        history: std::collections::VecDeque::new(),
                        is_recording: false,
                    }
                });

                entry.bytes_in += stats.bytes_recv;
                entry.bytes_out += stats.bytes_sent;
                entry.packets_in += stats.packets_recv;
                entry.packets_out += stats.packets_sent;
                entry.connection_count += 1;

                // Add connection info
                let country = self.geo_resolver.lookup(&stats.remote_addr);

                entry.connections.push(ConnectionInfo {
                    local_addr: stats.local_addr.clone(),
                    local_port: stats.local_port,
                    remote_addr: stats.remote_addr.clone(),
                    remote_port: stats.remote_port,
                    remote_domain: None, // Will be enriched by Store
                    protocol: stats.protocol.clone(),
                    state: stats.state.clone(),
                    bytes_recv: stats.bytes_recv,
                    bytes_sent: stats.bytes_sent,
                    rtt_ms: None, // Will be enriched by Store/Sniffer
                    inode: *inode,
                    country,
                    is_suspicious: false, // Will be enriched by Store
                });
            }
        }

        // Update store
        {
            let mut store = self.store.write();
            
            // Clear old port map? Or just overwrite.
            // Ideally we want to keep it fresh.
            // But Store manages it. Let's just update based on current connections.
            // We can't easily clear it without access to internal map structure or a clear method.
            // Let's rely on overwrites for now, or add a clear_port_map method.
            
            for (pid, metrics) in process_metrics {
                // Update port map for local ports of this process
                for conn in &metrics.connections {
                    store.update_port_map(conn.local_port, pid);
                }
                store.update_process(pid, metrics);
            }
            store.cleanup_stale();
        }

        // Save current stats for next iteration
        self.prev_socket_stats = current_stats;

        debug!("Collected {} sockets", self.prev_socket_stats.len());

        Ok(())
    }

    fn collect_socket_stats(&self) -> anyhow::Result<HashMap<u64, SocketStats>> {
        let mut stats = HashMap::new();

        // Try netlink first for TCP
        match netlink::get_tcp_sockets() {
            Ok(tcp_stats) => {
                for s in tcp_stats {
                    stats.insert(s.inode, s);
                }
            }
            Err(e) => {
                debug!("Netlink TCP failed, falling back to /proc: {}", e);
                // Fallback to /proc/net/tcp
                if let Ok(tcp_stats) = proc::parse_proc_net_tcp() {
                    for s in tcp_stats {
                        stats.insert(s.inode, s);
                    }
                }
            }
        }

        // Try netlink for UDP
        match netlink::get_udp_sockets() {
            Ok(udp_stats) => {
                for s in udp_stats {
                    stats.insert(s.inode, s);
                }
            }
            Err(e) => {
                debug!("Netlink UDP failed, falling back to /proc: {}", e);
                // Fallback to /proc/net/udp
                if let Ok(udp_stats) = proc::parse_proc_net_udp() {
                    for s in udp_stats {
                        stats.insert(s.inode, s);
                    }
                }
            }
        }

        Ok(stats)
    }
}
