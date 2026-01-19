# 📡 FlowSentinel

**FlowSentinel** is a high-performance, process-centric Linux network monitor and forensics tool. It provides a beautiful, interactive Terminal User Interface (TUI) to track network traffic at the process level, allowing you to identify exactly which application is talking to which server, how much bandwidth it consumes, and what domains it's resolving.


---

## ✨ Key Features

### 🚀 Real-time Monitoring
- **Process-Centric View**: Aggregate traffic by PID, UID, and process name.
- **Bandwidth Stats**: Live Bytes/s and Packets/s metrics for every process.
- **Sparklines**: 10-second bandwidth history graphs in the detail view.
- **Connection Tracking**: Live list of TCP/UDP connections with state (ESTABLISHED, LISTEN, etc.).

### 🔍 Deep Visibility (DPI)
- **TLS SNI Extraction**: See the actual domain names for encrypted HTTPS traffic.
- **HTTP Host Resolution**: Identify websites visited over unencrypted HTTP.
- **DNS History**: A scrollable history of all DNS queries made by a specific process with timestamps.
- **Remote Domain Mapping**: Automatically map remote IPs to seen hostnames in the connection list.

### 🛡️ Forensics & Security
- **PCAP Recording**: Record traffic for a specific process into standard `.pcap` files for Wireshark analysis.
- **Auto-PCAP Trigger**: Automatically start recording if a process exceeds a configurable bandwidth threshold.
- **SQLite Event Logging**: Persistently log every DNS query and connection event to a database for post-incident audits.
- **Threat Intelligence**: Highlight known malicious or suspicious IPs in **BOLD RED** using a custom blacklist.
- **RTT Tracking**: Measure network latency (Round-Trip Time) for active TCP connections.
- **Process Lineage**: View Parent PID (PPID) and full command lines to detect suspicious spawns.

### 🐳 Modern System Support
- **Container Awareness**: Automatically detects and labels Docker and Kubernetes (CRI-O/Containerd) container IDs.
- **GeoIP Integration**: Instantly see the country of origin for remote IP addresses.
- **Netlink Powered**: Uses high-performance Linux Netlink sockets (`inet_diag`) for efficient socket-to-PID mapping.

---

## 🛠️ Installation

### Prerequisites
- **Linux OS** (Kernel 4.0+ recommended).
- **libpcap-dev** & **libsqlite3-dev**: Required for packet capture and logging.
- **Rust**: MSRV 1.75+.

### Build and Install
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install libpcap-dev libsqlite3-dev

# Clone the repository
git clone https://github.com/your-username/FlowSentinel.git
cd FlowSentinel

# Option A: Build and run binary directly
cargo build --release
sudo ./target/release/flowsentinel

# Option B: Install through Debian package
wget https://github.com/disc0nct/FlowSentinel/releases/download/v1.0.0/flowsentinel_1.0.0-1_amd64.deb && sudo dpkg -i flowsentinel_1.0.0-1_amd64.deb
sudo flowsentinel
```

---

## 🚀 Usage

### Interactive TUI Mode
The default mode provides an interactive dashboard.
```bash
sudo ./target/release/flowsentinel
```

### Advanced Forensics & Logging
Log all network events to a SQLite database and set auto-pcap trigger at 5MB/s:
```bash
sudo ./target/release/flowsentinel --db network_audit.db --auto-pcap 5.0
```

Use a custom security blacklist to flag malicious IPs:
```bash
echo "8.8.8.8" > blacklist.txt
sudo ./target/release/flowsentinel --blacklist blacklist.txt
```

### Non-Interactive Mode (Streaming)
Stream metrics directly to your terminal as text:
```bash
sudo ./target/release/flowsentinel --non-interactive --top 10
```

### Snapshot Mode (Data Export)
Collect metrics for 30 seconds and save to a JSON file:
```bash
sudo ./target/release/flowsentinel snapshot --duration 30 --output report.json
```

---

## ⌨️ Controls & Keybindings

### 📊 Dashboard View
| Key | Action |
|-----|--------|
| `Arrows / j/k` | Navigate the process list |
| `Enter` | Open detailed view for the selected process |
| `x` | **Kill Process**: Send SIGTERM to the selected process |
| `/` | Filter processes by name, PID, or UID |
| `s` | Cycle sorting (Traffic, PID, Name, Connections) |
| `S` | Toggle sort direction (Ascending/Descending) |
| `r` | Pause/Resume live updates |
| `f` | Toggle **Follow Mode** (auto-focus top process) |
| `c` | Toggle compact mode (more rows, less detail) |
| `e` | Export current view to a timestamped JSON file |
| `q / Esc` | Quit application |
| `?` | Show help overlay |

### 🔍 Detail View
| Key | Action |
|-----|--------|
| `Tab` | Switch focus between **Connections** and **DNS Queries** |
| `j / k` | Scroll through the focused list |
| `Mouse Wheel` | Scroll through any list |
| `/` | Search/Filter within the detailed lists |
| `w` | Run a **WHOIS lookup** on the selected connection IP |
| `Shift + R` | Manually toggle **PCAP recording** for this process |
| `Esc` | Go back to the dashboard |

---

## ⚙️ Configuration (CLI Flags)

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interval <MS>` | UI update and collection interval in milliseconds | `200` |
| `--db <PATH>` | Path to SQLite database for persistent logging | - |
| `--blacklist <PATH>`| Path to IP blacklist file (one IP per line) | - |
| `--auto-pcap <MB>` | Auto-start PCAP if process exceeds bandwidth (MB/s) | - |
| `--interface <IF>` | Specific network interface to sniff (e.g., `eth0`) | Auto |
| `--history-ttl <S>`| How long to keep inactive connections in memory | `60` |
| `--top <N>` | Show only top N processes | All |
| `--log-level <LVL>` | Set log level (`debug`, `info`, `warn`, `error`) | `warn` |

---

## 📂 Data Storage
- **PCAP Files**: Saved in the current directory as `capture_<name>_<pid>_<timestamp>.pcap`.
- **SQLite Logs**: Tables `dns_logs` and `connection_logs` store historical events with high precision.
- **Exports**: Saved as `flowsentinel_export_<timestamp>.json`.

---

## 🏗️ Technical Architecture
FlowSentinel is built on a modular architecture:
1. **Collector**: Uses Netlink and `/proc` to map open sockets to PIDs.
2. **Sniffer**: Low-level packet capture using `pnet` to intercept traffic on all interfaces.
3. **Engine (Store)**: Thread-safe storage with `RwLock` for aggregating metrics and history.
4. **DPI Engine**: Real-time parsers for DNS (UDP/53), HTTP (TCP/80), and TLS (TCP/443).
5. **TUI**: Powered by `ratatui` for high-performance rendering.

---

## 📜 License
FlowSentinel is released under the **MIT License**.

---
*Created with ❤️ for the security and systems community. Monitor responsibly.*
