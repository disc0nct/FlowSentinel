use maxminddb::geoip2;
use std::net::IpAddr;

pub struct GeoResolver {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoResolver {
    pub fn new() -> Self {
        let paths = [
            "/usr/share/GeoIP/GeoLite2-City.mmdb",
            "/usr/share/GeoIP/GeoLite2-Country.mmdb",
            "./GeoLite2-City.mmdb",
            "./GeoLite2-Country.mmdb",
            "/var/lib/GeoIP/GeoLite2-City.mmdb",
        ];

        for path in paths {
            if let Ok(reader) = maxminddb::Reader::open_readfile(path) {
                return Self {
                    reader: Some(reader),
                };
            }
        }

        Self { reader: None }
    }

    pub fn lookup(&self, ip_str: &str) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let ip: IpAddr = ip_str.parse().ok()?;
        
        // Try City
        if let Ok(city) = reader.lookup::<geoip2::City>(ip) {
            if let Some(country) = city.country.and_then(|c| c.iso_code) {
                return Some(country.to_string());
            }
        }
        
        // Try Country
        if let Ok(country) = reader.lookup::<geoip2::Country>(ip) {
            if let Some(code) = country.country.and_then(|c| c.iso_code) {
                return Some(code.to_string());
            }
        }

        None
    }
}
