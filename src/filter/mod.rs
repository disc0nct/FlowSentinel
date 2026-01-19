use crate::collector::ProcessMetrics;

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub name: Option<String>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub port: Option<u16>,
    pub proto: Option<String>,
    pub ip: Option<String>,
}

/// Parse a filter string like "name:nginx port:443 uid:1000"
pub fn parse_filter(filter: &str) -> Filter {
    let mut result = Filter::default();

    for part in filter.split_whitespace() {
        if let Some((key, value)) = part.split_once(':') {
            match key.to_lowercase().as_str() {
                "name" => result.name = Some(value.to_string()),
                "pid" => result.pid = value.parse().ok(),
                "uid" => result.uid = value.parse().ok(),
                "port" => result.port = value.parse().ok(),
                "proto" | "protocol" => result.proto = Some(value.to_uppercase()),
                "ip" => result.ip = Some(value.to_string()),
                _ => {}
            }
        }
    }

    result
}

/// Check if a process matches the filter
pub fn matches_process(process: &ProcessMetrics, filter: &Filter) -> bool {
    // Check name filter
    if let Some(ref name_filter) = filter.name {
        if !process.name.to_lowercase().contains(&name_filter.to_lowercase()) {
            return false;
        }
    }

    // Check PID filter
    if let Some(pid_filter) = filter.pid {
        if process.pid != pid_filter {
            return false;
        }
    }

    // Check UID filter
    if let Some(uid_filter) = filter.uid {
        if process.uid != uid_filter {
            return false;
        }
    }

    // Check port filter (against connections)
    if let Some(port_filter) = filter.port {
        let has_port = process.connections.iter().any(|c| {
            c.local_port == port_filter || c.remote_port == port_filter
        });
        if !has_port {
            return false;
        }
    }

    // Check protocol filter
    if let Some(ref proto_filter) = filter.proto {
        let has_proto = process.connections.iter().any(|c| {
            c.protocol.to_uppercase() == proto_filter.to_uppercase()
        });
        if !has_proto {
            return false;
        }
    }

    // Check IP filter
    if let Some(ref ip_filter) = filter.ip {
        let has_ip = process.connections.iter().any(|c| {
            c.local_addr.contains(ip_filter) || c.remote_addr.contains(ip_filter)
        });
        if !has_ip {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_filter() {
        let filter = parse_filter("name:nginx port:443 uid:1000");
        assert_eq!(filter.name, Some("nginx".to_string()));
        assert_eq!(filter.port, Some(443));
        assert_eq!(filter.uid, Some(1000));
    }

    #[test]
    fn test_parse_empty_filter() {
        let filter = parse_filter("");
        assert!(filter.name.is_none());
        assert!(filter.pid.is_none());
    }
}
