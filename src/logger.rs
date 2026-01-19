use rusqlite::{params, Connection};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use tracing::{error, info};

pub enum LogEvent {
    Dns {
        pid: u32,
        name: String,
        query: String,
        timestamp: String,
    },
    Connection {
        pid: u32,
        name: String,
        local: String,
        remote: String,
        domain: Option<String>,
        proto: String,
        timestamp: String,
    },
}

pub struct NetworkLogger {
    tx: Sender<LogEvent>,
}

impl NetworkLogger {
    pub fn new(db_path: &str) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let path = db_path.to_string();

        thread::spawn(move || {
            if let Err(e) = Self::run_logger(&path, rx) {
                error!("Logger thread error: {}", e);
            }
        });

        Ok(Self { tx })
    }

    pub fn log(&self, event: LogEvent) {
        let _ = self.tx.send(event);
    }

    fn run_logger(path: &str, rx: Receiver<LogEvent>) -> anyhow::Result<()> {
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS dns_logs (
                id INTEGER PRIMARY KEY,
                pid INTEGER,
                process_name TEXT,
                query TEXT,
                timestamp TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS connection_logs (
                id INTEGER PRIMARY KEY,
                pid INTEGER,
                process_name TEXT,
                local_addr TEXT,
                remote_addr TEXT,
                domain TEXT,
                protocol TEXT,
                timestamp TEXT
            )",
            [],
        )?;

        info!("SQLite logger started at {}", path);

        while let Ok(event) = rx.recv() {
            match event {
                LogEvent::Dns { pid, name, query, timestamp } => {
                    let _ = conn.execute(
                        "INSERT INTO dns_logs (pid, process_name, query, timestamp) VALUES (?1, ?2, ?3, ?4)",
                        params![pid, name, query, timestamp],
                    );
                }
                LogEvent::Connection { pid, name, local, remote, domain, proto, timestamp } => {
                    let _ = conn.execute(
                        "INSERT INTO connection_logs (pid, process_name, local_addr, remote_addr, domain, protocol, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![pid, name, local, remote, domain, proto, timestamp],
                    );
                }
            }
        }

        Ok(())
    }
}
