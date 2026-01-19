use crate::store::Store;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use std::sync::Arc;
use std::thread;
use parking_lot::RwLock;
use tracing::{error, info};
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension};

pub fn start_sniffer(store: Arc<RwLock<Store>>, interface_name: Option<String>) {
    thread::spawn(move || {
        let interfaces = datalink::interfaces();
        
        let mut ifaces_to_sniff = Vec::new();

        if let Some(name) = interface_name {
            if let Some(iface) = interfaces.into_iter().find(|i| i.name == name) {
                ifaces_to_sniff.push(iface);
            } else {
                error!("Specified interface '{}' not found", name);
            }
        } else {
            if let Some(loopback) = interfaces.iter().find(|i| i.is_loopback() && i.is_up()) {
                ifaces_to_sniff.push(loopback.clone());
            }
            if let Some(external) = interfaces.iter().find(|i| !i.is_loopback() && i.is_up() && !i.ips.is_empty()) {
                ifaces_to_sniff.push(external.clone());
            }
        }

        for interface in ifaces_to_sniff {
            let store_clone = store.clone();
            thread::spawn(move || {
                info!("Sniffing traffic on interface: {}", interface.name);
                
                let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => {
                        error!("Unhandled channel type on {}", interface.name);
                        return;
                    }
                    Err(e) => {
                        error!("Failed to create datalink channel on {}: {}", interface.name, e);
                        return;
                    }
                };

                loop {
                    match rx.next() {
                        Ok(packet) => {
                            process_packet(packet, &store_clone);
                        }
                        Err(e) => {
                            error!("Failed to read packet on {}: {}", interface.name, e);
                        }
                    }
                }
            });
        }
    });
}

use pnet::packet::ipv6::Ipv6Packet;
use std::net::IpAddr;

// ... inside start_sniffer ...

fn process_packet(packet: &[u8], store: &Arc<RwLock<Store>>) {
    let ethernet = if let Some(eth) = EthernetPacket::new(packet) {
        eth
    } else {
        return;
    };

    let payload = ethernet.payload();
    let len = packet.len() as u64;

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(payload) {
                handle_ip_packet(
                    IpAddr::V4(ipv4.get_source()),
                    IpAddr::V4(ipv4.get_destination()),
                    ipv4.get_next_level_protocol(),
                    ipv4.payload(),
                    len,
                    packet,
                    store,
                );
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(payload) {
                handle_ip_packet(
                    IpAddr::V6(ipv6.get_source()),
                    IpAddr::V6(ipv6.get_destination()),
                    ipv6.get_next_header(),
                    ipv6.payload(),
                    len,
                    packet,
                    store,
                );
            }
        }
        _ => {}
    }
}

fn handle_ip_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    protocol: pnet::packet::ip::IpNextHeaderProtocol,
    payload: &[u8],
    len: u64,
    full_packet: &[u8],
    store: &Arc<RwLock<Store>>,
) {
    let src_ip_str = src_ip.to_string();
    let dst_ip_str = dst_ip.to_string();

    match protocol {
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(payload) {
                let source_port = udp.get_source();
                let dest_port = udp.get_destination();
                let udp_payload = udp.payload();

                // Recording
                {
                    let mut recorder = None;
                    if let Some(guard) = store.try_read() {
                        if let Some(pid) = guard.get_pid_by_port(source_port) {
                            if let Some(rec) = guard.get_recorder(pid) { recorder = Some(rec); }
                        }
                        if recorder.is_none() {
                            if let Some(pid) = guard.get_pid_by_port(dest_port) {
                                if let Some(rec) = guard.get_recorder(pid) { recorder = Some(rec); }
                            }
                        }
                    }
                    if let Some(rec) = recorder {
                        rec.write_packet(full_packet);
                    }
                }

                // 1. Update Traffic Stats
                if let Some(mut guard) = store.try_write() {
                    if let Some(pid) = guard.get_pid_by_port(source_port) {
                        guard.add_traffic(pid, 0, len, 0, 1, "UDP", source_port, &dst_ip_str, dest_port);
                    }
                    if let Some(pid) = guard.get_pid_by_port(dest_port) {
                        guard.add_traffic(pid, len, 0, 1, 0, "UDP", dest_port, &src_ip_str, source_port);
                    }
                }

                // 2. DNS Parsing (UDP port 53)
                if dest_port == 53 {
                    if let Ok(dns) = dns_parser::Packet::parse(udp_payload) {
                        for question in dns.questions {
                            let query_name = question.qname.to_string();
                            let pid_found = {
                                let guard = store.read();
                                guard.get_pid_by_port(source_port)
                            };

                            let mut final_pid = pid_found;
                            if final_pid.is_none() {
                                // Try netlink to find PID for this port
                                if let Ok(Some((inode, _))) = crate::collector::netlink::get_socket_info(17, source_port) {
                                    if let Ok(Some(pid)) = crate::collector::proc::find_pid_by_inode(inode) {
                                        final_pid = Some(pid);
                                        let mut guard = store.write();
                                        guard.update_port_map(source_port, pid);
                                    }
                                }
                            }

                            if let Some(pid) = final_pid {
                                let mut guard = store.write();
                                guard.add_dns_query(pid, query_name);
                            }
                        }
                    }
                }
            }
        }
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(payload) {
                let source_port = tcp.get_source();
                let dest_port = tcp.get_destination();
                let tcp_payload = tcp.payload();
                let flags = tcp.get_flags();

                // Recording
                {
                    let mut recorder = None;
                    if let Some(guard) = store.try_read() {
                        if let Some(pid) = guard.get_pid_by_port(source_port) {
                            if let Some(rec) = guard.get_recorder(pid) { recorder = Some(rec); }
                        }
                        if recorder.is_none() {
                            if let Some(pid) = guard.get_pid_by_port(dest_port) {
                                if let Some(rec) = guard.get_recorder(pid) { recorder = Some(rec); }
                            }
                        }
                    }
                    if let Some(rec) = recorder {
                        rec.write_packet(full_packet);
                    }
                }

                // 1. Update Traffic Stats & RTT
                if let Some(mut guard) = store.try_write() {
                    // RTT Tracking
                    if flags == pnet::packet::tcp::TcpFlags::SYN {
                        guard.record_syn(src_ip_str.clone(), source_port, dst_ip_str.clone(), dest_port);
                    } else if (flags & (pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK)) == (pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK) {
                        if let Some(rtt) = guard.calculate_rtt(src_ip_str.clone(), source_port, dst_ip_str.clone(), dest_port) {
                            if let Some(pid) = guard.get_pid_by_port(dest_port) {
                                guard.add_rtt_to_connection(pid, src_ip_str.clone(), source_port, rtt);
                            }
                        }
                    }

                    if let Some(pid) = guard.get_pid_by_port(source_port) {
                        guard.add_traffic(pid, 0, len, 0, 1, "TCP", source_port, &dst_ip_str, dest_port);
                    }
                    if let Some(pid) = guard.get_pid_by_port(dest_port) {
                        guard.add_traffic(pid, len, 0, 1, 0, "TCP", dest_port, &src_ip_str, source_port);
                    }
                }

                // 2. HTTP/TLS Parsing
                let mut domain = None;
                if dest_port == 80 && !tcp_payload.is_empty() {
                    domain = parse_http_host(tcp_payload);
                } else if dest_port == 443 && !tcp_payload.is_empty() {
                    domain = parse_tls_sni(tcp_payload);
                }

                if let Some(d) = domain {
                    {
                        let mut guard = store.write();
                        guard.add_domain_mapping(dst_ip_str.clone(), d.clone());
                    }

                    let pid_found = {
                        let guard = store.read();
                        guard.get_pid_by_port(source_port)
                    };

                    let mut final_pid = pid_found;
                    if final_pid.is_none() {
                        if let Ok(Some((inode, _))) = crate::collector::netlink::get_socket_info(6, source_port) {
                            if let Ok(Some(pid)) = crate::collector::proc::find_pid_by_inode(inode) {
                                final_pid = Some(pid);
                                let mut guard = store.write();
                                guard.update_port_map(source_port, pid);
                            }
                        }
                    }

                    if let Some(pid) = final_pid {
                        let mut guard = store.write();
                        guard.add_dns_query(pid, d);
                    }
                }
            }
        }
        _ => {}
    }
}

fn parse_http_host(payload: &[u8]) -> Option<String> {
    let mut headers = [httparse::Header { name: "", value: &[] }; 16];
    let mut req = httparse::Request::new(&mut headers);
    if let Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) = req.parse(payload) {
        if let Some(host) = req.headers.iter().find(|h| h.name.eq_ignore_ascii_case("Host")) {
            return String::from_utf8(host.value.to_vec()).ok();
        }
    }
    None
}

fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    if let Ok((_, msg)) = parse_tls_plaintext(payload) {
        for m in msg.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = m {
                if let Some(exts) = ch.ext {
                    if let Ok((_, extensions)) = tls_parser::parse_tls_extensions(exts) {
                        for ext in extensions {
                            if let TlsExtension::SNI(sni) = ext {
                                if let Some((_, name)) = sni.first() {
                                    return String::from_utf8(name.to_vec()).ok();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
