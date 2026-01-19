/// Format bytes into human-readable format
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let bytes = bytes as f64;

    if bytes >= TB {
        format!("{:.2} TB", bytes / TB)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes / KB)
    } else {
        format!("{:.0} B", bytes)
    }
}

/// Format a duration into human-readable format
pub fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d", secs / 86400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

/// Get service name for a port
pub fn get_service_name(port: u16, proto: &str) -> String {
    match port {
        53 => "DNS".to_string(),
        80 => "HTTP".to_string(),
        443 => "HTTPS".to_string(),
        22 => "SSH".to_string(),
        21 => "FTP".to_string(),
        25 => "SMTP".to_string(),
        123 => "NTP".to_string(),
        _ => proto.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
    }
}
