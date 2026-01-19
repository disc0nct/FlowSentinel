use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::info;

pub struct ThreatIntel {
    blacklist: HashSet<String>,
}

impl ThreatIntel {
    pub fn new(blacklist_path: Option<&str>) -> Self {
        let mut blacklist = HashSet::new();

        if let Some(path) = blacklist_path {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        blacklist.insert(line.to_string());
                    }
                }
                info!("Loaded {} blacklisted IPs from {}", blacklist.len(), path);
            }
        }

        Self { blacklist }
    }

    pub fn is_blacklisted(&self, ip: &str) -> bool {
        self.blacklist.contains(ip)
    }
}
