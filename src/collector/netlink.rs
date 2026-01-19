use super::SocketStats;
use anyhow::{Context, Result};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use tracing::debug;

fn tcp_state_to_string(state: u8) -> String {
    match state {
        1 => "ESTABLISHED".to_string(),
        2 => "SYN_SENT".to_string(),
        3 => "SYN_RECV".to_string(),
        4 => "FIN_WAIT1".to_string(),
        5 => "FIN_WAIT2".to_string(),
        6 => "TIME_WAIT".to_string(),
        7 => "CLOSE".to_string(),
        8 => "CLOSE_WAIT".to_string(),
        9 => "LAST_ACK".to_string(),
        10 => "LISTEN".to_string(),
        11 => "CLOSING".to_string(),
        _ => format!("UNKNOWN({})", state),
    }
}

pub fn get_tcp_sockets() -> Result<Vec<SocketStats>> {
    get_sockets(IPPROTO_TCP, "TCP")
}

pub fn get_udp_sockets() -> Result<Vec<SocketStats>> {
    get_sockets(IPPROTO_UDP, "UDP")
}

pub fn get_socket_info(protocol: u8, port: u16) -> Result<Option<(u64, u32)>> {
    // Determine family (try IPv4 then IPv6)
    // We construct a specific request for this port
    
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).context("Failed to create netlink socket")?;
    socket.bind_auto().context("Failed to bind netlink socket")?;
    socket.connect(&SocketAddr::new(0, 0)).context("Failed to connect netlink socket")?;

    // Try IPv4
    if let Ok(Some(info)) = query_single_socket(&mut socket, AF_INET as u8, protocol, port) {
        return Ok(Some(info));
    }
    
    // Try IPv6
    if let Ok(Some(info)) = query_single_socket(&mut socket, AF_INET6 as u8, protocol, port) {
        return Ok(Some(info));
    }

    Ok(None)
}

fn query_single_socket(
    socket: &mut Socket,
    family: u8,
    protocol: u8,
    port: u16,
) -> Result<Option<(u64, u32)>> {
    let state_flags = StateFlags::all();
    
    // Use InetRequest but we rely on filtering? 
    // Ideally we want to ask for a specific source port.
    // Standard inet_diag_req_v2 supports bytecode filters, but that's complex.
    // Simpler: Dump but filtered by kernel?
    // inet_diag allows filtering by src/dst.
    // But `netlink-packet-sock-diag` struct InetRequest doesn't expose the inet_diag_sockid easily for filtering in the REQUEST itself?
    // Wait, InetRequest HAS socket_id.
    // If we set socket_id.source_port, does the kernel filter?
    // Yes, if we provide the full ID. But we don't know the IP.
    
    // Fallback: Dump all (for that proto) and filter in userspace?
    // No, that's what we already do.
    
    // We want to avoid dumping 10k sockets.
    // If we can't filter by port only in kernel easily without bytecode, 
    // maybe we just dump. Dumping UDP is usually fast (fewer sockets than TCP).
    // Let's optimize: We only query UDP sockets (since DNS is UDP).
    
    let req = InetRequest {
        family,
        protocol,
        extensions: ExtensionFlags::empty(),
        states: state_flags,
        socket_id: SocketId::new_v4(), // Empty ID = Dump
    };

    let mut nl_msg = NetlinkMessage::from(SockDiagMessage::InetRequest(req));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_msg.finalize();

    let mut buf = vec![0u8; nl_msg.buffer_len()];
    nl_msg.serialize(&mut buf);

    socket.send(&buf, 0)?;

    let mut recv_buf = Vec::with_capacity(32768);
    
    loop {
        recv_buf.clear();
        let len = socket.recv(&mut recv_buf, 0)?;
        if len == 0 { break; }

        let mut offset = 0;
        loop {
            if offset >= len { break; }
            let buf_slice = &recv_buf[offset..len];
            let msg = NetlinkMessage::<SockDiagMessage>::deserialize(buf_slice);
            
            match msg {
                Ok(msg) => {
                    let aligned_len = (msg.header.length as usize + 3) & !3;
                    offset += aligned_len;

                    match msg.payload {
                        NetlinkPayload::Done(_) => return Ok(None),
                        NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                            if resp.header.socket_id.source_port == port {
                                return Ok(Some((resp.header.inode as u64, resp.header.uid)));
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => break,
            }
        }
    }
    
    Ok(None)
}

fn get_sockets(protocol: u8, proto_name: &str) -> Result<Vec<SocketStats>> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).context("Failed to create netlink socket")?;
    socket.bind_auto().context("Failed to bind netlink socket")?;
    socket.connect(&SocketAddr::new(0, 0)).context("Failed to connect netlink socket")?;

    let mut results = Vec::new();

    // Query IPv4
    results.extend(query_sockets(&mut socket, AF_INET as u8, protocol, proto_name)?);

    // Query IPv6
    results.extend(query_sockets(&mut socket, AF_INET6 as u8, protocol, proto_name)?);

    Ok(results)
}

fn query_sockets(
    socket: &mut Socket,
    family: u8,
    protocol: u8,
    proto_name: &str,
) -> Result<Vec<SocketStats>> {
    let mut results = Vec::new();

    let mut state_flags = StateFlags::empty();
    // Include all TCP states
    state_flags.insert(StateFlags::ESTABLISHED);
    state_flags.insert(StateFlags::SYN_SENT);
    state_flags.insert(StateFlags::SYN_RECV);
    state_flags.insert(StateFlags::FIN_WAIT1);
    state_flags.insert(StateFlags::FIN_WAIT2);
    state_flags.insert(StateFlags::TIME_WAIT);
    state_flags.insert(StateFlags::CLOSE);
    state_flags.insert(StateFlags::CLOSE_WAIT);
    state_flags.insert(StateFlags::LAST_ACK);
    state_flags.insert(StateFlags::LISTEN);
    state_flags.insert(StateFlags::CLOSING);

    let sock_id = SocketId::new_v4();

    let mut req = InetRequest {
        family,
        protocol,
        extensions: ExtensionFlags::INFO,
        states: state_flags,
        socket_id: sock_id,
    };

    if family == AF_INET6 as u8 {
        req.socket_id = SocketId::new_v6();
    }

    let mut nl_msg = NetlinkMessage::from(SockDiagMessage::InetRequest(req));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_msg.finalize();

    let mut buf = vec![0u8; nl_msg.buffer_len()];
    nl_msg.serialize(&mut buf);

    socket.send(&buf, 0).context("Failed to send netlink request")?;

    let mut recv_buf = Vec::with_capacity(65536);

    loop {
        recv_buf.clear();
        let len = socket.recv(&mut recv_buf, 0).context("Failed to receive netlink response")?;
        
        if len == 0 {
            break;
        }

        let mut offset = 0;
        loop {
            if offset >= len {
                break;
            }

            // Ensure we don't read past the received data
            let buf_slice = &recv_buf[offset..len];
            let msg = NetlinkMessage::<SockDiagMessage>::deserialize(buf_slice);
            match msg {
                Ok(msg) => {
                    // Netlink messages are 4-byte aligned
                    let aligned_len = (msg.header.length as usize + 3) & !3;
                    offset += aligned_len;

                    match msg.payload {
                        NetlinkPayload::Done(_) => {
                            return Ok(results);
                        }
                        NetlinkPayload::Error(e) => {
                            debug!("Netlink error: {:?}", e);
                            return Ok(results);
                        }
                        NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                            // IpAddr can be converted to string directly
                            let local_addr = resp.header.socket_id.source_address.to_string();
                            let remote_addr = resp.header.socket_id.destination_address.to_string();

                            let stats = SocketStats {
                                inode: resp.header.inode as u64,
                                local_addr,
                                local_port: resp.header.socket_id.source_port,
                                remote_addr,
                                remote_port: resp.header.socket_id.destination_port,
                                protocol: proto_name.to_string(),
                                state: tcp_state_to_string(resp.header.state),
                                bytes_recv: 0,
                                bytes_sent: 0,
                                packets_recv: 0,
                                packets_sent: 0,
                                uid: resp.header.uid,
                            };

                            results.push(stats);
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
    }

    Ok(results)
}
