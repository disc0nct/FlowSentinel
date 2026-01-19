use crate::collector::ProcessMetrics;
use crate::recorder::Recorder;
use crate::logger::{NetworkLogger, LogEvent};
use crate::threat_intel::ThreatIntel;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Store {
    processes: HashMap<u32, ProcessMetrics>,
    port_map: HashMap<u16, u32>,
    recorders: HashMap<u32, Recorder>,
    ip_domain_map: HashMap<String, String>,
    syn_timestamps: HashMap<(String, u16, String, u16), Instant>,
    logger: Option<Arc<NetworkLogger>>,
    threat_intel: Option<Arc<ThreatIntel>>,
    auto_pcap_threshold: Option<f64>,
    ttl: Duration,
}

impl Store {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            processes: HashMap::new(),
            port_map: HashMap::new(),
            recorders: HashMap::new(),
            ip_domain_map: HashMap::new(),
            syn_timestamps: HashMap::new(),
            logger: None,
            threat_intel: None,
            auto_pcap_threshold: None,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn set_threat_intel(&mut self, ti: Arc<ThreatIntel>) {
        self.threat_intel = Some(ti);
    }

    pub fn set_auto_pcap(&mut self, threshold_mbs: f64) {
        self.auto_pcap_threshold = Some(threshold_mbs);
    }

    pub fn set_logger(&mut self, logger: Arc<NetworkLogger>) {
        self.logger = Some(logger);
    }

    pub fn start_recording(&mut self, pid: u32, name: &str) -> anyhow::Result<String> {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("capture_{}_{}_{}.pcap", name.replace("/", "_"), pid, timestamp);
        let recorder = Recorder::new(&filename)?;
        
        self.recorders.insert(pid, recorder);
        if let Some(p) = self.processes.get_mut(&pid) {
            p.is_recording = true;
        }
        Ok(filename)
    }

    pub fn stop_recording(&mut self, pid: u32) {
        self.recorders.remove(&pid);
        if let Some(p) = self.processes.get_mut(&pid) {
            p.is_recording = false;
        }
    }

    pub fn get_recorder(&self, pid: u32) -> Option<Recorder> {
        self.recorders.get(&pid).cloned()
    }

    pub fn add_domain_mapping(&mut self, ip: String, domain: String) {
        self.ip_domain_map.insert(ip.clone(), domain.clone());
        
        if let Some(ref logger) = self.logger {
             // Try to find which process is talking to this IP
             for (pid, process) in &self.processes {
                 if process.connections.iter().any(|c| c.remote_addr == ip) {
                     logger.log(LogEvent::Connection {
                         pid: *pid,
                         name: process.name.clone(),
                         local: "-".to_string(),
                         remote: ip.clone(),
                         domain: Some(domain.clone()),
                         proto: "TCP".to_string(), // Usually TLS/HTTP is TCP
                         timestamp: chrono::Local::now().to_rfc3339(),
                     });
                     break;
                 }
             }
        }
    }

    pub fn record_syn(&mut self, src_ip: String, src_port: u16, dst_ip: String, dst_port: u16) {
        self.syn_timestamps.insert((src_ip, src_port, dst_ip, dst_port), Instant::now());
    }

    pub fn calculate_rtt(&mut self, src_ip: String, src_port: u16, dst_ip: String, dst_port: u16) -> Option<u32> {
        // SYN-ACK received, src and dst are swapped relative to SYN
        if let Some(start) = self.syn_timestamps.remove(&(dst_ip, dst_port, src_ip, src_port)) {
            return Some(start.elapsed().as_millis() as u32);
        }
        None
    }

    pub fn update_process(&mut self, pid: u32, metrics: ProcessMetrics) {
        let now = std::time::Instant::now();
        let mut should_start_pcap = None;
        
        if let Some(existing) = self.processes.get_mut(&pid) {
            // Update timestamp
            existing.last_seen = now;
            
            // Merge metadata
            existing.name = metrics.name;
            existing.ppid = metrics.ppid;
            existing.cmdline = metrics.cmdline;
            existing.uid = metrics.uid;
            existing.container_id = metrics.container_id;

            // Preserve recording state
            existing.is_recording = existing.is_recording || metrics.is_recording;
            
            // Merge connections
            // We want to keep connections seen by sniffer (which might have domains/RTT)
            // but also add new ones seen by collector.
            let mut new_conns = metrics.connections;
            for conn in &mut new_conns {
                // Enrich with domain if we have it in our global map
                if let Some(domain) = self.ip_domain_map.get(&conn.remote_addr) {
                    conn.remote_domain = Some(domain.clone());
                }
                
                // Enrich with threat intel
                if let Some(ref ti) = self.threat_intel {
                    if ti.is_blacklisted(&conn.remote_addr) {
                        conn.is_suspicious = true;
                    }
                }

                // Try to find if this connection was already enriched by sniffer
                // Match by inode first, then by ports/addr as fallback
                let old_conn = existing.connections.iter().find(|c| {
                    (c.inode > 0 && c.inode == conn.inode) || 
                    (c.local_port == conn.local_port && c.remote_port == conn.remote_port && c.remote_addr == conn.remote_addr)
                });

                if let Some(old) = old_conn {
                    if conn.remote_domain.is_none() { conn.remote_domain = old.remote_domain.clone(); }
                    if conn.rtt_ms.is_none() { conn.rtt_ms = old.rtt_ms; }
                    if !conn.is_suspicious { conn.is_suspicious = old.is_suspicious; }
                    // Carry over bytes if sniffer reported more
                    conn.bytes_recv = conn.bytes_recv.max(old.bytes_recv);
                    conn.bytes_sent = conn.bytes_sent.max(old.bytes_sent);
                }
            }
            existing.connections = new_conns;
            existing.connection_count = existing.connections.len();

            // Accumulate bytes (Master Totals)
            existing.bytes_in = existing.bytes_in.max(metrics.bytes_in);
            existing.bytes_out = existing.bytes_out.max(metrics.bytes_out);
            existing.packets_in = existing.packets_in.max(metrics.packets_in);
            existing.packets_out = existing.packets_out.max(metrics.packets_out);
            
            // Note: Protocol stats are updated in real-time by Sniffer via add_traffic
            // and we don't need to max them here because Collector doesn't provide them.
            // But we must ensure they are NOT overwritten by defaults.
            // The surgical merge already preserves 'existing.protocol_stats' because we are modifying 'existing' in place.

            // Rate calculation
            let last_update = existing.last_rate_update.unwrap_or(existing.last_seen);
            let duration = now.duration_since(last_update).as_secs_f64();
            
            if duration >= 1.0 {
                let bytes_total = existing.bytes_in + existing.bytes_out;
                let prev_bytes_total = existing.prev_bytes_in + existing.prev_bytes_out;
                let bytes_delta = bytes_total.saturating_sub(prev_bytes_total);
                
                let packets_total = existing.packets_in + existing.packets_out;
                let prev_packets_total = existing.prev_packets_in + existing.prev_packets_out;
                let packets_delta = packets_total.saturating_sub(prev_packets_total);
                
                existing.bytes_per_sec = bytes_delta as f64 / duration;
                existing.packets_per_sec = packets_delta as f64 / duration;
                
                existing.prev_bytes_in = existing.bytes_in;
                existing.prev_bytes_out = existing.bytes_out;
                existing.prev_packets_in = existing.packets_in;
                existing.prev_packets_out = existing.packets_out;
                existing.last_rate_update = Some(now);
                
                // Add to sparkline history
                existing.history.push_back(existing.bytes_per_sec as u64);
                if existing.history.len() > 10 {
                    existing.history.pop_front();
                }

                // Check Auto-PCAP trigger
                if let Some(threshold) = self.auto_pcap_threshold {
                    if !existing.is_recording && (existing.bytes_per_sec / 1_000_000.0) > threshold {
                         should_start_pcap = Some(existing.name.clone());
                    }
                }
            }
        } 
        else {
            let mut new_metrics = metrics;
            new_metrics.last_seen = now;
            new_metrics.prev_bytes_in = new_metrics.bytes_in;
            new_metrics.prev_bytes_out = new_metrics.bytes_out;
            new_metrics.prev_packets_in = new_metrics.packets_in;
            new_metrics.prev_packets_out = new_metrics.packets_out;
            new_metrics.last_rate_update = Some(now);
            self.processes.insert(pid, new_metrics);
        }

        if let Some(name) = should_start_pcap {
            let _ = self.start_recording(pid, &name);
        }
    }

    pub fn update_port_map(&mut self, port: u16, pid: u32) {
        self.port_map.insert(port, pid);
    }
    
    pub fn get_pid_by_port(&self, port: u16) -> Option<u32> {
        self.port_map.get(&port).copied()
    }

    pub fn add_dns_query(&mut self, pid: u32, query: String) {
        if let Some(process) = self.processes.get_mut(&pid) {
            let now = std::time::Instant::now();
            process.last_seen = now;
            
            let timestamp = chrono::Local::now();
            process.dns_queries.push(crate::collector::DnsQuery {
                query: query.clone(),
                timestamp,
            });

            if let Some(ref logger) = self.logger {
                logger.log(LogEvent::Dns {
                    pid,
                    name: process.name.clone(),
                    query,
                    timestamp: timestamp.to_rfc3339(),
                });
            }

            if process.dns_queries.len() > 100 {
                process.dns_queries.remove(0);
            }
        }
    }

    pub fn add_traffic(&mut self, pid: u32, bytes_in: u64, bytes_out: u64, pkts_in: u64, pkts_out: u64, proto: &str, local_port: u16, remote_addr: &str, remote_port: u16) {
        if let Some(p) = self.processes.get_mut(&pid) {
             p.last_seen = std::time::Instant::now();
             p.bytes_in += bytes_in;
             p.bytes_out += bytes_out;
             p.packets_in += pkts_in;
             p.packets_out += pkts_out;

             let total_bytes = bytes_in + bytes_out;
             match proto {
                 "TCP" => p.protocol_stats.tcp_bytes += total_bytes,
                 "UDP" => p.protocol_stats.udp_bytes += total_bytes,
                 "ICMP" => p.protocol_stats.icmp_bytes += total_bytes,
                 _ => {}
             }

             // Also update connection-specific stats
             for conn in &mut p.connections {
                 if conn.local_port == local_port && conn.remote_addr == remote_addr && conn.remote_port == remote_port {
                     conn.bytes_recv += bytes_in;
                     conn.bytes_sent += bytes_out;
                     break;
                 }
             }
        }
    }

    pub fn add_rtt_to_connection(&mut self, pid: u32, remote_addr: String, remote_port: u16, rtt_ms: u32) {
        if let Some(p) = self.processes.get_mut(&pid) {
            for conn in &mut p.connections {
                if conn.remote_addr == remote_addr && conn.remote_port == remote_port {
                    conn.rtt_ms = Some(rtt_ms);
                    break;
                }
            }
        }
    }

    pub fn get_process(&self, pid: u32) -> Option<&ProcessMetrics> {
        self.processes.get(&pid)
    }

    pub fn get_all_processes(&self) -> Vec<ProcessMetrics> {
        self.processes.values().cloned().collect()
    }

    pub fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.processes.retain(|_, metrics| {
            now.duration_since(metrics.last_seen) < self.ttl
        });

        // Cleanup stale SYN timestamps (older than 10s)
        self.syn_timestamps.retain(|_, &mut timestamp| {
            now.duration_since(timestamp) < Duration::from_secs(10)
        });

        // We should also clean up port map?
        // Ideally collector refreshes it completely.
    }


    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    pub fn total_bytes_per_sec(&self) -> f64 {
        self.processes.values().map(|p| p.bytes_per_sec).sum()
    }

    pub fn total_connections(&self) -> usize {
        self.processes.values().map(|p| p.connection_count).sum()
    }
}
