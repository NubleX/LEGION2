// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::shared::shared::{Observation, ObservationKind};
use anyhow::Result;
use regex::Regex;
use roxmltree::Document;
use std::collections::HashMap;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use std::sync::Arc;
use crate::database::Db;
// Removed circular import - these are defined in this file



#[derive(Debug, Clone)]
pub struct MacInfo {
    pub mac: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OsInfo {
    pub name: Option<String>,
    pub family: Option<String>,
    pub version: Option<String>,
    pub accuracy: Option<f32>,
    pub details: Option<String>,
}

pub struct OutputParser;

impl OutputParser {
    pub fn extract_ip_addresses(text: &str) -> Vec<String> {
        let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
        ip_regex
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    pub fn extract_ports(text: &str) -> Vec<u16> {
        let port_regex = Regex::new(r"\b(\d{1,5})/(?:tcp|udp)\b").unwrap();
        port_regex
            .captures_iter(text)
            .filter_map(|cap| cap.get(1)?.as_str().parse().ok())
            .collect()
    }

    pub fn extract_service_info(text: &str) -> Option<(String, Option<String>)> {
        // Basic service extraction - this would be more complex in reality
        if text.contains("http") {
            Some(("http".to_string(), None))
        } else if text.contains("ssh") {
            Some(("ssh".to_string(), None))
        } else if text.contains("ftp") {
            Some(("ftp".to_string(), None))
        } else {
            None
        }
    }

    pub fn parse_nmap_progress(line: &str) -> Option<f32> {
        let progress_regex = Regex::new(r"(\d+(?:\.\d+)?)%").unwrap();
        if let Some(cap) = progress_regex.captures(line) {
            cap.get(1)?.as_str().parse().ok()
        } else {
            None
        }
    }
}

/// Stateful parser for nmap output that tracks context between lines
#[derive(Debug, Default)]
pub struct NmapParser {
    /// Current host being processed
    current_host: Option<String>,
    /// Scan ID for all observations
    scan_id: Uuid,
    /// Host status cache to avoid duplicates
    host_status_reported: HashMap<String, bool>,
}

impl NmapParser {
    pub fn new(scan_id: Uuid) -> Self {
        Self {
            current_host: None,
            scan_id,
            host_status_reported: HashMap::new(),
        }
    }

    pub fn parse_line(&mut self, line: &str) -> Option<Observation> {
        // Parse "Nmap scan report for X.X.X.X"
        if line.contains("Nmap scan report for") {
            let ip = extract_ip_from_line(line)?;
            let ip_key = format!("host-{}", ip);
            return Some(Observation {
                scan_id: self.scan_id,
                kind: ObservationKind::Host,
                fields: {
                    let mut fields = serde_json::Map::new();
                    fields.insert("ip".to_string(), ip.into());
                    fields.insert("status".to_string(), "up".into());
                    fields
                },
                ts: chrono::Utc::now(),
                key: ip_key,
                raw: Some(line.to_string()),
            });
        }
    

        if line.is_empty() {
            return None;
        }

        // Check for host discovery line
        if line.contains("Nmap scan report for") {
            if let Some(ip) = line.split("for ").nth(1) {
                let clean_ip = ip
                    .trim()
                    .split_whitespace()
                    .next()
                    .unwrap_or(ip.trim())
                    .to_string();
                self.current_host = Some(clean_ip.clone());
                // Don't create observation yet - wait for status information
                return None;
            }
        }

        // Check for host status lines
        else if line.contains("Host is up") || line.contains("Host is down") {
            if let Some(ref current_ip) = self.current_host {
                let status = if line.contains("Host is up") {
                    "up"
                } else {
                    "down"
                };

                // Only report each host status once
                if !self.host_status_reported.get(current_ip).unwrap_or(&false) {
                    self.host_status_reported.insert(current_ip.clone(), true);

                    return Some(Observation {
                        scan_id: self.scan_id,
                        kind: ObservationKind::Host,
                        fields: {
                            let mut fields = serde_json::Map::new();
                            fields.insert("ip".to_string(), current_ip.clone().into());
                            fields.insert("status".to_string(), status.into());

                            // Extract latency if available
                            if let Some(latency_start) = line.find('(') {
                                if let Some(latency_end) = line.find(')') {
                                    let latency_info = &line[latency_start + 1..latency_end];
                                    if latency_info.contains("latency") {
                                        fields.insert("latency".to_string(), latency_info.into());
                                    }
                                }
                            }

                            fields
                        },
                        ts: chrono::Utc::now(),
                        key: format!("host-{}", current_ip),
                        raw: Some(line.to_string()),
                    });
                }
            }
        }
        // Check for MAC address lines
        else if line.contains("MAC Address:") {
            if let Some(current_ip) = self.current_host.clone() {
                if let Some(mac_info) = self.parse_mac_address(line) {
                    return Some(Observation {
                        scan_id: self.scan_id,
                        kind: ObservationKind::Host,
                        fields: {
                            let mut fields = serde_json::Map::new();
                            fields.insert("ip".to_string(), current_ip.clone().into());
                            fields.insert("mac_address".to_string(), mac_info.mac.into());
                            if let Some(vendor) = mac_info.vendor {
                                fields.insert("nic_vendor".to_string(), vendor.clone().into());
                                fields.insert("vendor".to_string(), vendor.into());
                            }
                            if let Some(model) = mac_info.model {
                                fields.insert("nic_model".to_string(), model.into());
                            }
                            fields.insert("type".to_string(), "mac_discovery".into());
                            fields
                        },
                        ts: chrono::Utc::now(),
                        key: format!("mac-{}", current_ip),
                        raw: Some(line.to_string()),
                    });
                }
            }
        }
        // Check for OS detection lines
        else if line.contains("OS details:") 
            || line.contains("Running:") 
            || line.contains("OS CPE:") 
            || line.contains("Aggressive OS guesses:")
        {
            if let Some(current_ip) = self.current_host.clone() {
                if let Some(os_info) = self.parse_os_detection(line) {
                    return Some(Observation {
                        scan_id: self.scan_id,
                        kind: ObservationKind::Host,
                        fields: {
                            let mut fields = serde_json::Map::new();
                            fields.insert("ip".to_string(), current_ip.clone().into());
                            if let Some(name) = os_info.name {
                                fields.insert("os_name".to_string(), name.into());
                            }
                            if let Some(family) = os_info.family {
                                fields.insert("os_family".to_string(), family.into());
                            }
                            if let Some(version) = os_info.version {
                                fields.insert("os_version".to_string(), version.into());
                            }
                            if let Some(accuracy) = os_info.accuracy {
                                fields.insert("os_accuracy".to_string(), accuracy.into());
                            }
                            if let Some(details) = os_info.details {
                                fields.insert("os_details".to_string(), details.into());
                            }
                            fields.insert("type".to_string(), "os_detection".into());
                            fields
                        },
                        ts: chrono::Utc::now(),
                        key: format!("os-{}", current_ip),
                        raw: Some(line.to_string()),
                    });
                }
            }
        }
        
        // Check for hostname resolution lines
        else if line.contains("rDNS record for")
            || (self.current_host.is_some()
                && line.contains(".")
                && !line.contains("/")
                && !line.contains("open"))
        {
            if let Some(current_ip) = self.current_host.clone() {
                if let Some(hostname) = self.parse_hostname(line) {
                    return Some(Observation {
                        scan_id: self.scan_id,
                        kind: ObservationKind::Host,
                        fields: {
                            let mut fields = serde_json::Map::new();
                            fields.insert("ip".to_string(), current_ip.clone().into());
                            fields.insert("hostname".to_string(), hostname.into());
                            fields.insert("type".to_string(), "hostname_discovery".into());
                            fields
                        },
                        ts: chrono::Utc::now(),
                        key: format!("hostname-{}", current_ip),
                        raw: Some(line.to_string()),
                    });
                }
            }
        }
        // Check for port discovery lines
        else if line.contains("open") && (line.contains("/tcp") || line.contains("/udp")) {
            // Parse port discovery: "22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Some(port_proto) = parts.get(0) {
                    let port_parts: Vec<&str> = port_proto.split('/').collect();
                    if port_parts.len() == 2 {
                        let port_str = port_parts[0];
                        let protocol = port_parts[1];
                        let state = parts[1];
                        let service = if parts.len() > 2 { parts[2] } else { "unknown" };

                        if let Some(ref current_ip) = self.current_host {
                            let key = format!("service-{}-{}-{}", current_ip, port_str, protocol);

                            return Some(Observation {
                                scan_id: self.scan_id,
                                kind: ObservationKind::Service,
                                fields: {
                                    let mut fields = serde_json::Map::new();
                                    fields.insert("ip".to_string(), current_ip.clone().into());
                                    fields.insert("port".to_string(), port_str.into());
                                    fields.insert("protocol".to_string(), protocol.into());
                                    fields.insert("state".to_string(), state.into());
                                    fields.insert("service".to_string(), service.into());

                                    // Add version info if available
                                    if parts.len() > 3 {
                                        let version_info: Vec<&str> = parts[3..].to_vec();
                                        fields.insert(
                                            "version".to_string(),
                                            version_info.join(" ").into(),
                                        );
                                    }
                                    fields
                                },
                                ts: chrono::Utc::now(),
                                key,
                                raw: Some(line.to_string()),
                            });
                        }
                    }
                }
            }
        }
        // Check for masscan-style output
        else if line.contains("Discovered open port") {
            if let Some(parts) = self.parse_discovered_port_line(line) {
                let key = format!("service-{}-{}-{}", parts.ip, parts.port, parts.protocol);
                return Some(Observation {
                    scan_id: self.scan_id,
                    kind: ObservationKind::Service,
                    fields: {
                        let mut fields = serde_json::Map::new();
                        fields.insert("ip".to_string(), parts.ip.into());
                        fields.insert("port".to_string(), parts.port.into());
                        fields.insert("protocol".to_string(), parts.protocol.into());
                        fields.insert("state".to_string(), "open".into());
                        fields.insert("reason".to_string(), "discovered".into());
                        fields
                    },
                    ts: chrono::Utc::now(),
                    key,
                    raw: Some(line.to_string()),
                });
            }
        }
        // Check for scan progress lines
        else if line.contains("Scanning")
            || line.contains("Completed")
            || line.contains("Initiating")
            || line.contains("Nmap done")
        {
            return Some(Observation {
                scan_id: self.scan_id,
                kind: ObservationKind::Metric,
                fields: {
                    let mut fields = serde_json::Map::new();
                    fields.insert("message".to_string(), line.into());
                    fields.insert("type".to_string(), "scan_progress".into());
                    fields
                },
                ts: chrono::Utc::now(),
                key: "scan-progress".to_string(),
                raw: Some(line.to_string()),
            });
        } else {
            // For lines that don't match specific patterns, create raw output metric
            return Some(Observation {
                scan_id: self.scan_id,
                kind: ObservationKind::Metric,
                fields: {
                    let mut fields = serde_json::Map::new();
                    fields.insert("message".to_string(), line.into());
                    fields.insert("type".to_string(), "raw_output".into());
                    fields
                },
                ts: chrono::Utc::now(),
                key: format!("raw-{}", chrono::Utc::now().timestamp_nanos()),
                raw: Some(line.to_string()),
            });
        }
        
        None
    }
        
    /// Parse MAC address lines from nmap output
    fn parse_mac_address(&mut self, line: &str) -> Option<MacInfo> {
        // Parse "MAC Address: 00:11:22:33:44:55 (Vendor Name)"
        // Also handle formats like "MAC Address: XX:XX:XX:XX:XX:XX (Unknown)"
        let mac_regex = Regex::new(r"MAC Address:\s+([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})(?:\s+\(([^)]+)\))?").unwrap();
        if let Some(captures) = mac_regex.captures(line) {
            let mac = captures.get(1)?.as_str().to_string();
            let vendor = captures
                .get(2)
                .map(|m| m.as_str().to_string())
                .filter(|v| !v.is_empty() && v != "Unknown" && v != "unknown");

            return Some(MacInfo { mac, vendor, model: None });
        }

        None
    }

    /// Parse OS detection information from nmap output with enhanced patterns
    fn parse_os_detection(&mut self, line: &str) -> Option<OsInfo> {
        use regex::Regex;

        // "OS details: Linux 3.2 - 4.9"
        if line.starts_with("OS details:") {
            let details = line.strip_prefix("OS details:")?.trim().to_string();
            let (family, version) = self.extract_os_family_and_version(&details);
            return Some(OsInfo {
                name: Some(details.clone()),
                family: Some(family),
                version,
                accuracy: Some(90.0), // High confidence for OS details
                details: Some(details),
            });
        }

        // "Running: Linux 3.X|4.X"
        if line.starts_with("Running:") {
            let running_info = line.strip_prefix("Running:")?.trim().to_string();
            let (family, version) = self.extract_os_family_and_version(&running_info);
            return Some(OsInfo {
                name: Some(running_info.clone()),
                family: Some(family),
                version,
                accuracy: Some(85.0), // Good confidence for running info
                details: Some(running_info),
            });
        }

        // Enhanced Windows pattern matching
        if let Some(caps) = Regex::new(r"(?i)microsoft\s+windows\s+(nt\s+)?(\d+\.?\d*|\w+)")
            .unwrap()
            .captures(line)
        {
            if let Some(version) = caps.get(2) {
                let version_str = version.as_str();
                let name = format!("Microsoft Windows {}", version_str);
                return Some(OsInfo {
                    name: Some(name.clone()),
                    family: Some("Windows".to_string()),
                    version: Some(version_str.to_string()),
                    accuracy: Some(88.0),
                    details: Some(name),
                });
            }
        }

        // Enhanced Linux pattern matching
        if let Some(caps) = Regex::new(r"(?i)linux\s+(kernel\s+)?(\d+\.\d+\.?\d*)")
            .unwrap()
            .captures(line)
        {
            if let Some(version) = caps.get(2) {
                let version_str = version.as_str();
                let name = format!("Linux {}", version_str);
                return Some(OsInfo {
                    name: Some(name.clone()),
                    family: Some("Linux".to_string()),
                    version: Some(version_str.to_string()),
                    accuracy: Some(85.0),
                    details: Some(name),
                });
            }
        }

        // Enhanced macOS pattern matching
        if let Some(caps) = Regex::new(r"(?i)(mac\s*os\s*x?|darwin)\s*(\d+\.?\d*\.?\d*)?")
            .unwrap()
            .captures(line)
        {
            let version = caps.get(2).map(|m| m.as_str().to_string());
            let name = if let Some(ref v) = version {
                format!("Apple macOS {}", v)
            } else {
                "Apple macOS".to_string()
            };
            return Some(OsInfo {
                name: Some(name.clone()),
                family: Some("macOS".to_string()),
                version,
                accuracy: Some(82.0),
                details: Some(name),
            });
        }

        // FreeBSD pattern
        if let Some(caps) = Regex::new(r"(?i)freebsd\s*(\d+\.?\d*\.?\d*)?")
            .unwrap()
            .captures(line)
        {
            let version = caps.get(1).map(|m| m.as_str().to_string());
            let name = if let Some(ref v) = version {
                format!("FreeBSD {}", v)
            } else {
                "FreeBSD".to_string()
            };
            return Some(OsInfo {
                name: Some(name.clone()),
                family: Some("BSD".to_string()),
                version,
                accuracy: Some(80.0),
                details: Some(name),
            });
        }

        // Running detection - fallback patterns
        if line.starts_with("Running:") {
            let running_info = line.strip_prefix("Running:")?.trim().to_string();
            let (family, version) = self.extract_os_family_and_version(&running_info);
            return Some(OsInfo {
                name: Some(running_info.clone()),
                family: Some(family),
                version,
                accuracy: None,
                details: Some(running_info),
            });
        }

        // "Aggressive OS guesses: Linux 3.2 - 4.9 (95%)"
        if line.starts_with("Aggressive OS guesses:") {
            let guess_info = line.strip_prefix("Aggressive OS guesses:")?.trim();

            // Extract accuracy percentage if available
            let accuracy = if let Some(paren_start) = guess_info.rfind('(') {
                if let Some(paren_end) = guess_info.rfind(')') {
                    let percent_str = &guess_info[paren_start + 1..paren_end];
                    if percent_str.ends_with('%') {
                        percent_str.trim_end_matches('%').parse::<f32>().ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Remove accuracy info to get clean OS name
            let clean_name = if let Some(paren_start) = guess_info.rfind('(') {
                guess_info[..paren_start].trim().to_string()
            } else {
                guess_info.to_string()
            };

            let (family, version) = self.extract_os_family_and_version(&clean_name);
            return Some(OsInfo {
                name: Some(clean_name.clone()),
                family: Some(family),
                version,
                accuracy,
                details: Some(guess_info.to_string()),
            });
        }

        // "OS CPE: cpe:/o:linux:linux_kernel:3"
        if line.starts_with("OS CPE:") {
            let cpe_info = line.strip_prefix("OS CPE:")?.trim();
            if let Some(os_info) = self.parse_cpe_string(cpe_info) {
                return Some(os_info);
            }
        }

        None
    }

    /// Extract OS family and version from OS description
    /// TTL-based OS detection for passive fingerprinting  
    pub fn detect_os_by_ttl(&mut self, ttl: u8) -> Option<OsInfo> {
        let (name, family, accuracy) = match ttl {
            // Linux/Unix systems typically use TTL 64
            64 => ("Linux/Unix", "Linux", 85.0),
            // Windows systems typically use TTL 128
            128 => ("Microsoft Windows", "Windows", 90.0),
            // Network devices/routers often use TTL 255
            255 => ("Network Device/Router", "Network", 80.0),
            // Some older systems or custom configurations
            32 => ("Legacy Unix/DOS", "Unix", 70.0),
            // Some BSD variants use TTL 64 but can be distinguished
            63..=65 => ("BSD/Linux Variant", "Unix", 75.0),
            // Windows variants
            127..=129 => ("Windows Variant", "Windows", 85.0),
            // Low confidence for unusual TTLs
            _ => return None,
        };

        Some(OsInfo {
            name: Some(name.to_string()),
            family: Some(family.to_string()),
            version: None, // TTL doesn't give version info
            accuracy: Some(accuracy),
            details: Some(format!("TTL-based detection (TTL={})", ttl)),
        })
    }

    /// Enhanced TCP signature analysis for passive OS detection
    pub fn analyze_tcp_signature(
        &mut self,
        window_size: u16,
        ttl: u8,
        tcp_options: &[String],
    ) -> Option<OsInfo> {
        // Advanced fingerprinting based on TCP stack behavior

        // Windows-specific signatures
        if ttl == 128 && window_size == 65535 {
            return Some(OsInfo {
                name: Some("Microsoft Windows (TCP signature)".to_string()),
                family: Some("Windows".to_string()),
                version: None,
                accuracy: Some(88.0),
                details: Some(format!("TCP signature: TTL={}, WIN={}", ttl, window_size)),
            });
        }

        // Linux-specific signatures
        if ttl == 64 && tcp_options.contains(&"wscale".to_string()) {
            return Some(OsInfo {
                name: Some("Linux (TCP signature)".to_string()),
                family: Some("Linux".to_string()),
                version: None,
                accuracy: Some(85.0),
                details: Some(format!(
                    "TCP signature: TTL={}, WIN={}, WSCALE",
                    ttl, window_size
                )),
            });
        }

        // macOS signatures
        if ttl == 64 && window_size == 65535 && tcp_options.contains(&"nop".to_string()) {
            return Some(OsInfo {
                name: Some("Apple macOS (TCP signature)".to_string()),
                family: Some("macOS".to_string()),
                version: None,
                accuracy: Some(80.0),
                details: Some(format!("TCP signature: TTL={}, WIN={}", ttl, window_size)),
            });
        }

        // Fallback to TTL-only detection
        self.detect_os_by_ttl(ttl)
    }

    /// HTTP header-based OS detection
    pub fn detect_os_from_http_headers(
        &mut self,
        server_header: &str,
        _other_headers: &std::collections::HashMap<String, String>,
    ) -> Option<OsInfo> {
        use regex::Regex;

        // IIS detection (Windows)
        if let Some(caps) = Regex::new(r"(?i)microsoft-iis/(\d+\.?\d*)")
            .unwrap()
            .captures(server_header)
        {
            let version = caps.get(1).map(|m| m.as_str().to_string());
            return Some(OsInfo {
                name: Some("Microsoft Windows (IIS)".to_string()),
                family: Some("Windows".to_string()),
                version,
                accuracy: Some(92.0),
                details: Some(format!("HTTP Server: {}", server_header)),
            });
        }

        // Apache on Ubuntu/Linux
        if server_header.to_lowercase().contains("apache")
            && server_header.to_lowercase().contains("ubuntu")
        {
            return Some(OsInfo {
                name: Some("Ubuntu Linux".to_string()),
                family: Some("Linux".to_string()),
                version: None,
                accuracy: Some(85.0),
                details: Some(format!("HTTP Server: {}", server_header)),
            });
        }

        // nginx detection (usually Linux)
        if server_header.to_lowercase().contains("nginx") {
            return Some(OsInfo {
                name: Some("Linux/Unix (nginx)".to_string()),
                family: Some("Linux".to_string()),
                version: None,
                accuracy: Some(75.0),
                details: Some(format!("HTTP Server: {}", server_header)),
            });
        }

        None
    }

    /// Parse comprehensive host information from nmap XML output
    pub fn parse_host_xml(&mut self, xml_content: &str) -> Result<Vec<Observation>> {
        let mut observations = Vec::new();

        // Parse XML document
        let doc = Document::parse(xml_content)?;

        // Find all host elements
        for host_node in doc.descendants().filter(|n| n.tag_name().name() == "host") {
            if let Ok(host_obs) = self.create_comprehensive_host_observation(&host_node) {
                observations.push(host_obs);

                // Also create service observations for each port
                for port_node in host_node
                    .descendants()
                    .filter(|n| n.tag_name().name() == "port")
                {
                    if let Ok(service_obs) =
                        self.create_service_observation_from_xml(&host_node, &port_node)
                    {
                        observations.push(service_obs);
                    }
                }
            }
        }

        Ok(observations)
    }

    /// Create comprehensive host observation from XML node (like legacy Host.rs)
    fn create_comprehensive_host_observation(
        &mut self,
        host_node: &roxmltree::Node,
    ) -> Result<Observation> {
        let mut fields = serde_json::Map::new();

        // Parse host status
        if let Some(status_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "status")
        {
            if let Some(status) = status_node.attribute("state") {
                fields.insert("status".to_string(), status.into());
            }
        }

        // Parse addresses (IPv4, IPv6, MAC)
        let mut primary_ip = String::new();
        for addr_node in host_node
            .children()
            .filter(|n| n.tag_name().name() == "address")
        {
            let addr_type = addr_node.attribute("addrtype").unwrap_or("");
            let addr = addr_node.attribute("addr").unwrap_or("");

            match addr_type {
                "ipv4" => {
                    fields.insert("ipv4".to_string(), addr.into());
                    if primary_ip.is_empty() {
                        primary_ip = addr.to_string();
                        fields.insert("ip".to_string(), addr.into());
                    }
                }
                "ipv6" => {
                    fields.insert("ipv6".to_string(), addr.into());
                    if primary_ip.is_empty() {
                        primary_ip = addr.to_string();
                        fields.insert("ip".to_string(), addr.into());
                    }
                }
                "mac" => {
                    fields.insert("mac_address".to_string(), addr.into());
                    if let Some(vendor) = addr_node.attribute("vendor") {
                        fields.insert("vendor".to_string(), vendor.into());
                    }
                }
                _ => {}
            }
        }

        // Parse hostname
        if let Some(hostname_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "hostnames")
            .and_then(|n| n.children().find(|n| n.tag_name().name() == "hostname"))
        {
            if let Some(hostname) = hostname_node.attribute("name") {
                fields.insert("hostname".to_string(), hostname.into());
            }
        }

        // Parse uptime information
        if let Some(uptime_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "uptime")
        {
            if let Some(seconds) = uptime_node.attribute("seconds") {
                fields.insert("uptime".to_string(), seconds.into());
            }
            if let Some(lastboot) = uptime_node.attribute("lastboot") {
                fields.insert("lastboot".to_string(), lastboot.into());
            }
        }

        // Parse distance
        if let Some(distance_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "distance")
        {
            if let Some(distance) = distance_node.attribute("value") {
                fields.insert("distance".to_string(), distance.into());
            }
        }

        // Parse OS information
        for osclass_node in host_node
            .children()
            .filter(|n| n.tag_name().name() == "osclass")
        {
            if let Some(os_family) = osclass_node.attribute("osfamily") {
                fields.insert("os_family".to_string(), os_family.into());
            }
            if let Some(os_type) = osclass_node.attribute("type") {
                fields.insert("os_type".to_string(), os_type.into());
            }
            if let Some(vendor) = osclass_node.attribute("vendor") {
                fields.insert("os_vendor".to_string(), vendor.into());
            }
            if let Some(accuracy) = osclass_node.attribute("accuracy") {
                fields.insert("os_accuracy".to_string(), accuracy.into());
            }
        }

        for osmatch_node in host_node
            .children()
            .filter(|n| n.tag_name().name() == "osmatch")
        {
            if let Some(os_name) = osmatch_node.attribute("name") {
                fields.insert("os_name".to_string(), os_name.into());
            }
            if let Some(accuracy) = osmatch_node.attribute("accuracy") {
                fields.insert("os_accuracy".to_string(), accuracy.into());
            }
        }

        // Parse extraports
        if let Some(extraports_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "extraports")
        {
            if let Some(state) = extraports_node.attribute("state") {
                fields.insert("extraports_state".to_string(), state.into());
            }
            if let Some(count) = extraports_node.attribute("count") {
                fields.insert("extraports_count".to_string(), count.into());
            }
        }

        let key = format!("host-{}", primary_ip);

        Ok(Observation {
            scan_id: self.scan_id,
            kind: ObservationKind::Host,
            fields,
            ts: chrono::Utc::now(),
            key,
            raw: None, // XML is too large to store as raw
        })
    }

    /// Create service observation from XML port node
    fn create_service_observation_from_xml(
        &mut self,
        host_node: &roxmltree::Node,
        port_node: &roxmltree::Node,
    ) -> Result<Observation> {
        let mut fields = serde_json::Map::new();

        // Get host IP
        let host_ip = host_node
            .children()
            .find(|n| n.tag_name().name() == "address" && n.attribute("addrtype") == Some("ipv4"))
            .and_then(|n| n.attribute("addr"))
            .unwrap_or("");
        fields.insert("ip".to_string(), host_ip.into());

        // Get port information
        if let Some(portid) = port_node.attribute("portid") {
            fields.insert("port".to_string(), portid.into());
        }
        if let Some(protocol) = port_node.attribute("protocol") {
            fields.insert("protocol".to_string(), protocol.into());
        }

        // Get state information
        if let Some(state_node) = port_node
            .children()
            .find(|n| n.tag_name().name() == "state")
        {
            if let Some(state) = state_node.attribute("state") {
                fields.insert("state".to_string(), state.into());
            }
            if let Some(reason) = state_node.attribute("reason") {
                fields.insert("reason".to_string(), reason.into());
            }
        }

        // Get service information
        if let Some(service_node) = port_node
            .children()
            .find(|n| n.tag_name().name() == "service")
        {
            if let Some(name) = service_node.attribute("name") {
                fields.insert("service".to_string(), name.into());
            }
            if let Some(product) = service_node.attribute("product") {
                fields.insert("product".to_string(), product.into());
            }
            if let Some(version) = service_node.attribute("version") {
                fields.insert("version".to_string(), version.into());
            }
            if let Some(extrainfo) = service_node.attribute("extrainfo") {
                fields.insert("extrainfo".to_string(), extrainfo.into());
            }
        }

        let port = port_node.attribute("portid").unwrap_or("0");
        let protocol = port_node.attribute("protocol").unwrap_or("tcp");
        let key = format!("service-{}-{}-{}", host_ip, port, protocol);

        Ok(Observation {
            scan_id: self.scan_id,
            kind: ObservationKind::Service,
            fields,
            ts: chrono::Utc::now(),
            key,
            raw: None,
        })
    }

    fn extract_os_family_and_version(&mut self, os_desc: &str) -> (String, Option<String>) {
        let lower_desc = os_desc.to_lowercase();

        // Detect common OS families
        let family = if lower_desc.contains("linux") {
            "Linux".to_string()
        } else if lower_desc.contains("windows") {
            "Windows".to_string()
        } else if lower_desc.contains("macos")
            || lower_desc.contains("mac os")
            || lower_desc.contains("darwin")
        {
            "macOS".to_string()
        } else if lower_desc.contains("freebsd") {
            "FreeBSD".to_string()
        } else if lower_desc.contains("openbsd") {
            "OpenBSD".to_string()
        } else if lower_desc.contains("netbsd") {
            "NetBSD".to_string()
        } else if lower_desc.contains("solaris") {
            "Solaris".to_string()
        } else if lower_desc.contains("aix") {
            "AIX".to_string()
        } else {
            "Unknown".to_string()
        };

        // Extract version using regex patterns
        let version = self.extract_version_from_description(os_desc);

        (family, version)
    }

    /// Extract version information from OS description
    fn extract_version_from_description(&mut self, desc: &str) -> Option<String> {
        // Pattern for version numbers like "3.2", "4.9", "10.15", etc.
        let version_regex = Regex::new(r"(\d+(?:\.\d+)*(?:\.\w+)?)").unwrap();

        // Look for common version patterns
        if let Some(captures) = version_regex.captures(desc) {
            return Some(captures.get(1)?.as_str().to_string());
        }

        None
    }

    /// Parse CPE (Common Platform Enumeration) strings
    fn parse_cpe_string(&mut self, cpe: &str) -> Option<OsInfo> {
        // CPE format: cpe:/o:vendor:product:version
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() >= 4 && parts[0] == "cpe" && parts[1] == "/o" {
            let vendor = parts[2];
            let product = parts[3];
            let version = if parts.len() > 4 && !parts[4].is_empty() {
                Some(parts[4].to_string())
            } else {
                None
            };

            let name = format!("{} {}", vendor, product);
            let family = self.vendor_to_family(vendor);

            return Some(OsInfo {
                name: Some(name),
                family: Some(family),
                version,
                accuracy: None,
                details: Some(cpe.to_string()),
            });
        }

        None
    }

    /// Map vendor names to OS families
    fn vendor_to_family(&mut self, vendor: &str) -> String {
        match vendor.to_lowercase().as_str() {
            "linux" => "Linux".to_string(),
            "microsoft" => "Windows".to_string(),
            "apple" => "macOS".to_string(),
            "freebsd" => "FreeBSD".to_string(),
            "openbsd" => "OpenBSD".to_string(),
            "netbsd" => "NetBSD".to_string(),
            "sun" | "oracle" => "Solaris".to_string(),
            "ibm" => "AIX".to_string(),
            _ => vendor.to_string(),
        }
    }

    /// Parse hostname from nmap output
    fn parse_hostname(&mut self, line: &str) -> Option<String> {
        // "rDNS record for 192.168.1.1: hostname.domain.com"
        if line.contains("rDNS record for") {
            if let Some(colon_pos) = line.find(':') {
                let hostname = line[colon_pos + 1..].trim();
                if !hostname.is_empty() && hostname != "N/A" {
                    return Some(hostname.to_string());
                }
            }
        }

        // Also try to extract from "Nmap scan report for hostname (ip)" format
        if line.contains("Nmap scan report for") && line.contains('(') {
            if let Some(for_pos) = line.find("for ") {
                if let Some(paren_pos) = line.find('(') {
                    let hostname = line[for_pos + 4..paren_pos].trim();
                    // Make sure it's not just an IP address
                    if hostname.contains('.')
                        && !hostname.chars().all(|c| c.is_ascii_digit() || c == '.')
                    {
                        return Some(hostname.to_string());
                    }
                }
            }
        }

        None
    }

    /// Parse masscan-style "Discovered open port" lines
    fn parse_discovered_port_line(&mut self, line: &str) -> Option<DiscoveredPort> {
        // "Discovered open port 80/tcp on 192.168.1.1"
        if let Some(port_start) = line.find("port ") {
            let after_port = &line[port_start + 5..];
            if let Some(on_pos) = after_port.find(" on ") {
                let port_proto = &after_port[..on_pos];
                let ip_part = &after_port[on_pos + 4..];

                if let Some(slash_pos) = port_proto.find('/') {
                    let port = &port_proto[..slash_pos];
                    let protocol = &port_proto[slash_pos + 1..];
                    let ip = ip_part
                        .trim()
                        .split_whitespace()
                        .next()
                        .unwrap_or(ip_part.trim());

                    return Some(DiscoveredPort {
                        ip: ip.to_string(),
                        port: port.to_string(),
                        protocol: protocol.to_string(),
                    });
                }
            }
        }
        None
    }

    /// Reset parser state for a new scan
    pub fn reset(&mut self, scan_id: Uuid) {
        self.current_host = None;
        self.scan_id = scan_id;
        self.host_status_reported.clear();
    }

    /// Get the current host being processed
    pub fn current_host(&mut self) -> Option<&String> {
        self.current_host.as_ref()
    }
}

/// Helper function to extract IP address from nmap scan report line
fn extract_ip_from_line(line: &str) -> Option<String> {
    // Extract IP from "Nmap scan report for X.X.X.X" or "Nmap scan report for hostname (X.X.X.X)"
    if let Some(for_pos) = line.find("for ") {
        let after_for = &line[for_pos + 4..];
        
        // Case 1: "for X.X.X.X"
        let ip_part = after_for.trim().split_whitespace().next().unwrap_or("");
        
        // Check if it's an IP address
        let ip_regex = regex::Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
        if ip_regex.is_match(ip_part) {
            return Some(ip_part.to_string());
        }
        
        // Case 2: "for hostname (X.X.X.X)"
        if let Some(paren_start) = after_for.find('(') {
            if let Some(paren_end) = after_for.find(')') {
                let ip_in_parens = &after_for[paren_start + 1..paren_end];
                if ip_regex.is_match(ip_in_parens.trim()) {
                    return Some(ip_in_parens.trim().to_string());
                }
            }
        }
    }
    
    None
}

#[derive(Debug)]
struct DiscoveredPort {
    ip: String,
    port: String,
    protocol: String,
}
