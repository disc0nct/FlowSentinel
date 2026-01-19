use super::SocketStats;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::debug;

/// Build a mapping from socket inode to PID by scanning /proc/<pid>/fd
pub fn build_socket_to_pid_map() -> Result<HashMap<u64, u32>> {
    let mut map = HashMap::new();

    let proc_dir = fs::read_dir("/proc")?;

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Check if this is a PID directory
        if let Ok(pid) = name.parse::<u32>() {
            let fd_path = format!("/proc/{}/fd", pid);

            if let Ok(fd_dir) = fs::read_dir(&fd_path) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();

                        // Look for socket:[inode] pattern
                        if link_str.starts_with("socket:[") {
                            if let Some(inode_str) = link_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    map.insert(inode, pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    debug!("Built socket->pid map with {} entries", map.len());
    Ok(map)
}

/// Find PID for a specific socket inode (optimized scan)
pub fn find_pid_by_inode(target_inode: u64) -> Result<Option<u32>> {
    let proc_dir = fs::read_dir("/proc")?;

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if let Ok(pid) = name.parse::<u32>() {
            let fd_path = format!("/proc/{}/fd", pid);

            if let Ok(fd_dir) = fs::read_dir(&fd_path) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") {
                            if let Some(inode_str) = link_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    if inode == target_inode {
                                        return Ok(Some(pid));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Get process name, UID, PPID, cmdline and Container ID from /proc/<pid>
pub fn get_process_info(pid: u32) -> Option<(String, u32, Option<u32>, Option<String>, Option<String>)> {
    let comm_path = format!("/proc/{}/comm", pid);
    let status_path = format!("/proc/{}/status", pid);
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let cgroup_path = format!("/proc/{}/cgroup", pid);

    let name = fs::read_to_string(&comm_path)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("pid:{}", pid));

    let mut uid = 0;
    let mut ppid = None;
    if let Ok(content) = fs::read_to_string(&status_path) {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    uid = parts[1].parse::<u32>().unwrap_or(0);
                }
            } else if line.starts_with("PPid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    ppid = parts[1].parse::<u32>().ok();
                }
            }
        }
    }

    let cmdline = fs::read_to_string(&cmdline_path)
        .ok()
        .map(|s| {
            let s = s.replace('\0', " ").trim().to_string();
            if s.is_empty() { name.clone() } else { s }
        });

    let mut container_id = None;
    if let Ok(content) = fs::read_to_string(cgroup_path) {
        for line in content.lines() {
            if line.contains("docker") || line.contains("kubepods") {
                let parts: Vec<&str> = line.split('/').collect();
                for part in parts {
                    if part.len() == 64 && part.chars().all(|c| c.is_ascii_hexdigit()) {
                        container_id = Some(part[0..12].to_string());
                        break;
                    }
                    if let Some(id) = part.strip_prefix("docker-").or_else(|| part.strip_prefix("cri-containerd-")) {
                         if let Some(clean_id) = id.strip_suffix(".scope") {
                             if clean_id.len() >= 12 {
                                 container_id = Some(clean_id[0..12].to_string());
                                 break;
                             }
                         }
                    }
                }
            }
            if container_id.is_some() { break; }
        }
    }

    Some((name, uid, ppid, cmdline, container_id))
}

/// Parse /proc/net/tcp for TCP socket information
pub fn parse_proc_net_tcp() -> Result<Vec<SocketStats>> {
    let mut stats = Vec::new();

    // Parse IPv4
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        stats.extend(parse_proc_net_file(&content, "TCP", false)?);
    }

    // Parse IPv6
    if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
        stats.extend(parse_proc_net_file(&content, "TCP", true)?);
    }

    Ok(stats)
}

/// Parse /proc/net/udp for UDP socket information
pub fn parse_proc_net_udp() -> Result<Vec<SocketStats>> {
    let mut stats = Vec::new();

    // Parse IPv4
    if let Ok(content) = fs::read_to_string("/proc/net/udp") {
        stats.extend(parse_proc_net_file(&content, "UDP", false)?);
    }

    // Parse IPv6
    if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
        stats.extend(parse_proc_net_file(&content, "UDP", true)?);
    }

    Ok(stats)
}

fn parse_proc_net_file(content: &str, protocol: &str, is_ipv6: bool) -> Result<Vec<SocketStats>> {
    let mut stats = Vec::new();

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 10 {
            continue;
        }

        // Parse local address
        let local_parts: Vec<&str> = parts[1].split(':').collect();
        if local_parts.len() != 2 {
            continue;
        }

        let local_addr = parse_hex_addr(local_parts[0], is_ipv6);
        let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);

        // Parse remote address
        let remote_parts: Vec<&str> = parts[2].split(':').collect();
        if remote_parts.len() != 2 {
            continue;
        }

        let remote_addr = parse_hex_addr(remote_parts[0], is_ipv6);
        let remote_port = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);

        // Parse state
        let state = u8::from_str_radix(parts[3], 16).unwrap_or(0);
        let state_str = tcp_state_to_string(state);

        // Parse tx/rx queue for approximate bytes (not accurate, just queue depth)
        let queues: Vec<&str> = parts[4].split(':').collect();
        let tx_queue = if queues.len() > 0 {
            u64::from_str_radix(queues[0], 16).unwrap_or(0)
        } else {
            0
        };
        let rx_queue = if queues.len() > 1 {
            u64::from_str_radix(queues[1], 16).unwrap_or(0)
        } else {
            0
        };

        // Parse UID
        let uid = parts[7].parse::<u32>().unwrap_or(0);

        // Parse inode
        let inode = parts[9].parse::<u64>().unwrap_or(0);

        if inode == 0 {
            continue;
        }

        stats.push(SocketStats {
            inode,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            protocol: protocol.to_string(),
            state: state_str,
            bytes_recv: rx_queue,
            bytes_sent: tx_queue,
            packets_recv: 0,
            packets_sent: 0,
            uid,
        });
    }

    Ok(stats)
}

fn parse_hex_addr(hex: &str, is_ipv6: bool) -> String {
    if is_ipv6 {
        if hex.len() == 32 {
            // IPv6 address in hex (32 chars = 16 bytes)
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
            }
            // Bytes are stored in network order but need to be reversed per 4-byte group
            let mut fixed = [0u8; 16];
            for i in 0..4 {
                fixed[i * 4] = bytes[i * 4 + 3];
                fixed[i * 4 + 1] = bytes[i * 4 + 2];
                fixed[i * 4 + 2] = bytes[i * 4 + 1];
                fixed[i * 4 + 3] = bytes[i * 4];
            }
            Ipv6Addr::from(fixed).to_string()
        } else {
            "::".to_string()
        }
    } else {
        if hex.len() == 8 {
            // IPv4 address in little-endian hex
            let addr = u32::from_str_radix(hex, 16).unwrap_or(0);
            Ipv4Addr::from(addr.to_be()).to_string()
        } else {
            "0.0.0.0".to_string()
        }
    }
}

fn tcp_state_to_string(state: u8) -> String {
    match state {
        0x01 => "ESTABLISHED".to_string(),
        0x02 => "SYN_SENT".to_string(),
        0x03 => "SYN_RECV".to_string(),
        0x04 => "FIN_WAIT1".to_string(),
        0x05 => "FIN_WAIT2".to_string(),
        0x06 => "TIME_WAIT".to_string(),
        0x07 => "CLOSE".to_string(),
        0x08 => "CLOSE_WAIT".to_string(),
        0x09 => "LAST_ACK".to_string(),
        0x0A => "LISTEN".to_string(),
        0x0B => "CLOSING".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
}
