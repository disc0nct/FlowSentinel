# 📡 FlowSentinel

**FlowSentinel** is a high-performance, interactive TUI network traffic monitor for Linux. Unlike traditional tools that show global traffic, FlowSentinel provides a **process-centric** view, allowing you to see exactly which application is consuming your bandwidth, where it's connecting, and what domains it's resolving.

Built in Rust for speed and safety, it leverages Netlink and Packet Inspection to provide deep visibility into your system's network behavior.

---

## ✨ Key Features

- **🚀 Real-time Monitoring**: Track per-process bandwidth (Bytes/s, Packets/s) and active connections.
- **🔍 Deep Packet Inspection (DPI)**:
  - **TLS SNI Extraction**: See the actual domain names for encrypted HTTPS traffic.
  - **HTTP Host Resolution**: Identify websites being visited over unencrypted HTTP.
  - **DNS History**: A scrollable history of all DNS queries made by a specific process.
- **🛡️ Forensics & Security**:
  - **PCAP Recording**: Record traffic for a specific process into a standard `.pcap` file for analysis in Wireshark.
  - **Threat Intel**: Load a blacklist of malicious IPs to highlight suspicious connections in **BOLD RED**.
  - **RTT Tracking**: Measure network latency (Round-Trip Time) for active TCP connections.
  - **Process Lineage**: View Parent PID (PPID) and full command lines.
- **📊 Analytics & Export**:
  - **SQLite Logging**: Persistently log all network events to a database for post-incident audits.
  - **Protocol Distribution**: Visualize traffic breakdown by TCP, UDP, and ICMP.
  - **Export View**: Export current process snapshots to JSON or CSV.
- **🐳 Container Awareness**: Automatically detects and labels Docker/Containerd container IDs.
- **🌍 GeoIP Integration**: Instantly see the country of origin for remote IP addresses.

---

## 🛠️ Installation

### Prerequisites
- **Linux OS** (Uses Netlink and `/proc` filesystem)
- **Rust** (MSRV 1.75+)
- **Build Essentials**: `libpcap-dev`, `libsqlite3-dev`

### Build from Source
```bash
# Clone the repository
git clone https://github.com/your-username/FlowSentinel.git
cd FlowSentinel

# Build in release mode
cargo build --release

# Run with root privileges (required for raw socket sniffing)
sudo ./target/release/flowsentinel
```

---

## 🚀 Usage

### Basic Mode
```bash
sudo ./target/release/flowsentinel
```

### Advanced Forensics & Logging
```bash
# Log all network events to a SQLite database and set auto-pcap trigger at 10MB/s
sudo ./target/release/flowsentinel --db audit.sqlite --auto-pcap 10.0

# Use a custom security blacklist to flag malicious IPs
sudo ./target/release/flowsentinel --blacklist my_threat_feed.txt
```

### CLI Arguments
| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interval` | Update interval in milliseconds | `200` |
| `--db <PATH>` | Path to SQLite database for persistent logging | - |
| `--blacklist <PATH>`| Path to IP blacklist file (one IP per line) | - |
| `--auto-pcap <MB>` | Auto-start PCAP if process exceeds bandwidth | - |
| `--interface <IF>` | Specific network interface to sniff | Auto-detect |
| `--history-ttl <S>`| How long to keep inactive connections in UI | `60` |

---

## ⌨️ Keybindings & Controls

### Main Dashboard
- **`Arrows / j/k`**: Navigate process list.
- **`Enter`**: View detailed info for selected process.
- **`/`**: Filter processes by name or PID.
- **`s`**: Cycle sorting (Traffic, PID, Name, Connections).
- **`x`**: Send SIGTERM to the selected process (Kill).
- **`e`**: Export current view to JSON.
- **`q / Esc`**: Quit application.

### Detail View
- **`Tab`**: Switch focus between **Connections** and **DNS Queries**.
- **`j/k`**: Scroll the focused list.
- **`w`**: Run a WHOIS lookup on the selected connection IP.
- **`Shift + R`**: Manually toggle PCAP recording for this process.
- **`/`**: Search/Filter within the detailed lists.
- **`Esc`**: Back to dashboard.

---

## 🏗️ Requirements
- **Root Privileges**: Required to attach to network interfaces and read process file descriptors.
- **libpcap**: Used for packet capture functionality.

---

## 📜 License
FlowSentinel is released under the **MIT License**. See `LICENSE` for details.

---
*Created with ❤️ for the security and systems community.*
