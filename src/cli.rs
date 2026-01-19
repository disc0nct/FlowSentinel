use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(name = "flowsentinel")]
#[command(author = "FlowSentinel Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Interactive TUI network traffic monitor per application/process", long_about = None)]
pub struct Cli {
    /// Run in non-interactive mode (output to stdout)
    #[arg(long, default_value_t = false)]
    pub non_interactive: bool,

    /// Output format as JSON (non-interactive mode)
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Output format as CSV (non-interactive mode)
    #[arg(long, default_value_t = false)]
    pub csv: bool,

    /// Update interval in milliseconds
    #[arg(long, short = 'i', default_value_t = 200)]
    pub interval: u64,

    /// Show only top N processes
    #[arg(long)]
    pub top: Option<usize>,

    /// Filter expression (e.g., "name:nginx port:443 uid:1000")
    #[arg(long, short = 'f')]
    pub filter: Option<String>,

    /// Focus on specific PID
    #[arg(long)]
    pub pid: Option<u32>,

    /// Follow mode - auto-focus top process
    #[arg(long, default_value_t = false)]
    pub follow: bool,

    /// Log level (debug, info, warn, error)
    #[arg(long, default_value = "warn")]
    pub log_level: String,

    /// History TTL in seconds for per-connection data
    #[arg(long, default_value_t = 60)]
    pub history_ttl: u64,

    /// Path to SQLite database for logging network events
    #[arg(long)]
    pub db: Option<String>,

    /// Path to a text file containing blacklisted IPs (one per line)
    #[arg(long)]
    pub blacklist: Option<String>,

    /// Auto-trigger PCAP recording if a process exceeds this bandwidth (MB/s)
    #[arg(long)]
    pub auto_pcap: Option<f64>,

    /// Enable deep inspection (TLS SNI, HTTP Host) - requires elevated privileges
    #[arg(long, default_value_t = false)]
    pub inspect: bool,

    /// Network interface to sniff (e.g., eth0, wlan0). Auto-detected if not specified.
    #[arg(long)]
    pub interface: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Collect metrics for a duration and export
    Snapshot {
        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Collection duration in seconds
        #[arg(long, short = 'd', default_value_t = 30)]
        duration: u64,

        /// Output format (json or csv)
        #[arg(long, default_value = "json")]
        format: String,
    },
}
