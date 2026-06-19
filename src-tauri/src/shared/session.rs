// Add these dependencies to Cargo.toml:
// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// serde_xml_rs = "0.6"
// roxmltree = "0.18"
// chrono = { version = "0.4", features = ["serde"] }
// anyhow = "1.0"
// thiserror = "1.0"

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    pub start_time: Option<DateTime<Utc>>,
    pub finish_time: Option<DateTime<Utc>>,
    pub nmap_version: String,
    pub scan_args: String,
    pub total_hosts: u32,
    pub up_hosts: u32,
    pub down_hosts: u32,
    pub scan_type: String,
    pub protocol: String,
    pub num_services: u32,
    pub services_scanned: Vec<u16>,
}

impl Session {
    pub fn from_xml_node(nmap_run_node: &roxmltree::Node) -> Result<Self> {
        // Parse timing information
        let start_time = nmap_run_node
            .attribute("start")
            .and_then(|s| s.parse::<i64>().ok())
            .map(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0))
            .flatten();

        // Parse finish time from scaninfo
        let finish_time = nmap_run_node
            .children()
            .find(|n| n.tag_name().name() == "finished")
            .and_then(|node| node.attribute("time"))
            .and_then(|s| s.parse::<i64>().ok())
            .map(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0))
            .flatten();

        // Parse nmap version
        let nmap_version = nmap_run_node.attribute("version").unwrap_or("").to_string();

        // Parse scan arguments
        let scan_args = nmap_run_node.attribute("args").unwrap_or("").to_string();

        // Parse scan info
        let mut scan_type = String::new();
        let mut protocol = String::new();
        let mut num_services = 0u32;
        let mut services_scanned = Vec::new();

        if let Some(scaninfo_node) = nmap_run_node
            .children()
            .find(|n| n.tag_name().name() == "scaninfo")
        {
            scan_type = scaninfo_node.attribute("type").unwrap_or("").to_string();
            protocol = scaninfo_node
                .attribute("protocol")
                .unwrap_or("")
                .to_string();
            num_services = scaninfo_node
                .attribute("numservices")
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);

            // Parse services if available
            if let Some(services_str) = scaninfo_node.attribute("services") {
                services_scanned = Self::parse_services(services_str);
            }
        }

        // Parse host counts from runstats
        let mut total_hosts = 0u32;
        let mut up_hosts = 0u32;
        let mut down_hosts = 0u32;

        if let Some(runstats_node) = nmap_run_node
            .children()
            .find(|n| n.tag_name().name() == "runstats")
        {
            if let Some(hosts_node) = runstats_node
                .children()
                .find(|n| n.tag_name().name() == "hosts")
            {
                total_hosts = hosts_node
                    .attribute("total")
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                up_hosts = hosts_node
                    .attribute("up")
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                down_hosts = hosts_node
                    .attribute("down")
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
            }
        }

        Ok(Session {
            start_time,
            finish_time,
            nmap_version,
            scan_args,
            total_hosts,
            up_hosts,
            down_hosts,
            scan_type,
            protocol,
            num_services,
            services_scanned,
        })
    }

    fn parse_services(services_str: &str) -> Vec<u16> {
        let mut services = Vec::new();

        for part in services_str.split(',') {
            if part.contains('-') {
                // Range of services
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() == 2 {
                    if let (Ok(start), Ok(end)) =
                        (range_parts[0].parse::<u16>(), range_parts[1].parse::<u16>())
                    {
                        services.extend(start..=end);
                    }
                }
            } else {
                // Single service
                if let Ok(port) = part.parse::<u16>() {
                    services.push(port);
                }
            }
        }

        services.sort();
        services.dedup();
        services
    }

    pub fn duration(&self) -> Option<chrono::Duration> {
        match (self.start_time, self.finish_time) {
            (Some(start), Some(end)) => Some(end.signed_duration_since(start)),
            _ => None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.finish_time.is_some()
    }

    pub fn hosts_up_percentage(&self) -> f64 {
        if self.total_hosts == 0 {
            0.0
        } else {
            (self.up_hosts as f64 / self.total_hosts as f64) * 100.0
        }
    }

    pub fn scan_summary(&self) -> String {
        format!(
            "Nmap {} scan completed. {} hosts up ({:.1}%) out of {} total hosts. Scan took {:?}",
            self.nmap_version,
            self.up_hosts,
            self.hosts_up_percentage(),
            self.total_hosts,
            self.duration().unwrap_or_else(|| chrono::Duration::zero())
        )
    }

    pub fn was_interrupted(&self) -> bool {
        // Check if scan was interrupted based on finish reason
        if let Some(finish_node) = self.get_finish_node() {
            if let Some(reason) = finish_node.attribute("reason") {
                return reason == "cancelled" || reason == "interrupted";
            }
        }
        false
    }

    fn get_finish_node(&self) -> Option<roxmltree::Node> {
        // This would require storing the original XML node or parsing it again
        // In a real implementation, you might store this information during parsing
        None
    }
}

// Session parser that processes entire Nmap XML output
pub struct SessionParser;

impl SessionParser {
    pub fn parse_nmap_xml(xml_content: &str) -> Result<Session> {
        let doc =
            roxmltree::Document::parse(xml_content).context("Failed to parse XML document")?;

        let nmap_run_node = doc.root().first_child().context("No root element found")?;

        if nmap_run_node.tag_name().name() != "nmaprun" {
            anyhow::bail!("Root element is not 'nmaprun'");
        }

        Session::from_xml_node(&nmap_run_node)
    }

    pub fn parse_nmap_file(file_path: &str) -> Result<Session> {
        let content = std::fs::read_to_string(file_path).context("Failed to read Nmap XML file")?;

        Self::parse_nmap_xml(&content)
    }
}

// Enhanced session with additional analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAnalytics {
    pub session: Session,
    pub scan_efficiency: f64, // hosts up / time taken
    pub ports_per_host: f64,  // average ports scanned per host
    pub scan_intensity: ScanIntensity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanIntensity {
    Light,     // < 100 ports
    Moderate,  // 100-1000 ports
    Heavy,     // 1000-10000 ports
    Intensive, // > 10000 ports
}

impl SessionAnalytics {
    pub fn from_session(session: Session) -> Self {
        let scan_efficiency = if let Some(duration) = session.duration() {
            if duration.num_seconds() > 0 {
                session.up_hosts as f64 / duration.num_seconds() as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        let ports_per_host = if session.total_hosts > 0 {
            session.num_services as f64 / session.total_hosts as f64
        } else {
            0.0
        };

        let scan_intensity = match session.num_services {
            0..=99 => ScanIntensity::Light,
            100..=999 => ScanIntensity::Moderate,
            1000..=9999 => ScanIntensity::Heavy,
            _ => ScanIntensity::Intensive,
        };

        Self {
            session,
            scan_efficiency,
            ports_per_host,
            scan_intensity,
        }
    }

    pub fn performance_rating(&self) -> &'static str {
        if self.scan_efficiency > 10.0 {
            "Excellent"
        } else if self.scan_efficiency > 5.0 {
            "Good"
        } else if self.scan_efficiency > 1.0 {
            "Average"
        } else {
            "Slow"
        }
    }
}

// Session manager for handling multiple sessions
pub struct SessionManager {
    sessions: Vec<Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    pub fn add_session(&mut self, session: Session) {
        self.sessions.push(session);
    }

    pub fn get_latest_session(&self) -> Option<&Session> {
        self.sessions.last()
    }

    pub fn get_sessions_by_version(&self, version: &str) -> Vec<&Session> {
        self.sessions
            .iter()
            .filter(|s| s.nmap_version == version)
            .collect()
    }

    pub fn get_average_scan_time(&self) -> Option<chrono::Duration> {
        if self.sessions.is_empty() {
            return None;
        }

        let total_duration: chrono::Duration =
            self.sessions.iter().filter_map(|s| s.duration()).sum();

        Some(total_duration / self.sessions.len() as i32)
    }

    pub fn get_total_hosts_scanned(&self) -> u32 {
        self.sessions.iter().map(|s| s.total_hosts).sum()
    }
}
