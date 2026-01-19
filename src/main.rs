mod cli;
mod collector;
mod export;
mod filter;
mod geoip;
mod logger;
mod recorder;
mod sniffer;
mod store;
mod threat_intel;
mod ui;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{Level, error};
use tracing_subscriber::FmtSubscriber;

use collector::Collector;
use store::Store;
use geoip::GeoResolver;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.log_level.as_str() {
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    // Create shared store with RwLock
    let store = Arc::new(RwLock::new(Store::new(cli.history_ttl)));
    
    // Initialize SQLite logger if path is provided
    if let Some(ref db_path) = cli.db {
        match logger::NetworkLogger::new(db_path) {
            Ok(logger) => {
                store.write().set_logger(Arc::new(logger));
            }
            Err(e) => {
                error!("Failed to initialize SQLite logger: {}", e);
            }
        }
    }

    // Set Auto-PCAP threshold if provided
    if let Some(threshold) = cli.auto_pcap {
        store.write().set_auto_pcap(threshold);
    }

    // Initialize Threat Intel if blacklist is provided
    if let Some(ref path) = cli.blacklist {
        let ti = Arc::new(threat_intel::ThreatIntel::new(Some(path)));
        store.write().set_threat_intel(ti);
    }
    
    // Create GeoIP resolver
    let geo_resolver = Arc::new(GeoResolver::new());

    // Start Sniffer (if privileges allow)
    sniffer::start_sniffer(store.clone(), cli.interface.clone());

    // Create collector
    let collector = Collector::new(Arc::clone(&store), geo_resolver);
    let interval = cli.interval;

    match &cli.command {
        Some(Commands::Snapshot {
            output,
            duration,
            format,
        }) => {
            // Snapshot mode: collect for duration and export
            let collector_handle = tokio::spawn({
                let mut collector = collector;
                async move {
                    collector.run(interval).await;
                }
            });

            tokio::time::sleep(std::time::Duration::from_secs(*duration)).await;
            collector_handle.abort();

            let store_guard = store.read();
            let processes = store_guard.get_all_processes();

            match format.as_str() {
                "csv" => {
                    let csv_output = export::to_csv(&processes)?;
                    if let Some(path) = output {
                        std::fs::write(path, csv_output)?;
                        println!("Snapshot written to {}", path);
                    } else {
                        print!("{}", csv_output);
                    }
                }
                _ => {
                    let json_output = export::to_json(&processes)?;
                    if let Some(path) = output {
                        std::fs::write(path, json_output)?;
                        println!("Snapshot written to {}", path);
                    } else {
                        println!("{}", json_output);
                    }
                }
            }
        }
        None => {
            if cli.non_interactive {
                // Non-interactive mode: output to stdout
                run_non_interactive(collector, store, &cli).await?;
            } else {
                // Interactive TUI mode
                ui::run(collector, store, cli).await?;
            }
        }
    }

    Ok(())
}

async fn run_non_interactive(
    collector: Collector,
    store: Arc<RwLock<Store>>,
    cli: &Cli,
) -> Result<()> {
    let interval_ms = cli.interval;
    let _collector_handle = tokio::spawn({
        let mut collector = collector;
        async move {
            collector.run(interval_ms).await;
        }
    });

    let top_n = cli.top;
    let json_output = cli.json;
    let csv_output = cli.csv;

    let filter_str = cli.filter.clone();

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;

        let store_guard = store.read();
        let mut processes = store_guard.get_all_processes();

        // Apply filter if specified
        if let Some(ref filter) = filter_str {
            let parsed = filter::parse_filter(filter);
            processes.retain(|p| filter::matches_process(p, &parsed));
        }

        // Sort by bytes per second descending
        processes.sort_by(|a, b| b.bytes_per_sec.total_cmp(&a.bytes_per_sec));

        // Limit to top N
        if let Some(n) = top_n {
            processes.truncate(n);
        }

        if json_output {
            if let Ok(output) = export::to_json(&processes) {
                println!("{}", output);
            }
        } else if csv_output {
            if let Ok(output) = export::to_csv(&processes) {
                print!("{}", output);
            }
        } else {
            // Simple text output
            println!("\n--- Network Traffic Snapshot ---");
            println!(
                "{:<20} {:<8} {:<6} {:>12} {:>12} {:>8} {:<20}",
                "NAME", "PID", "UID", "BYTES/S", "PKTS/S", "CONNS", "LAST DNS"
            );
            for p in &processes {
                let last_dns = p.dns_queries.last().map(|s| s.query.as_str()).unwrap_or("");
                println!(
                    "{:<20} {:<8} {:<6} {:>12.1} {:>12.1} {:>8} {:<20}",
                    truncate_str(&p.name, 20),
                    p.pid,
                    p.uid,
                    p.bytes_per_sec,
                    p.packets_per_sec,
                    p.connection_count,
                    truncate_str(last_dns, 20)
                );
            }
        }
    }

    #[allow(unreachable_code)]
    {
        _collector_handle.abort();
        Ok(())
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}
