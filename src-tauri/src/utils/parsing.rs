// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.

// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security

//     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
//     License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
//     version.

//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
//     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//     details.

//     You should have received a copy of the GNU General Public License along with this program.
//     If not, see <http://www.gnu.org/licenses/>.

use regex::Regex;
use anyhow::Result;
use std::collections::HashMap;
use uuid::Uuid;
use crate::shared::{Observation, ObservationKind};

#[derive(Debug, Clone)]
pub struct MacInfo {
    pub mac: String,
    pub vendor: Option<String>,
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

    /// Parse a line of nmap output and return an observation if applicable
    pub fn parse_line(&mut self, line: &str) -> Option<Observation> {
        let line = line.trim();
        
        if line.is_empty() {
            return None;
        }

        // Check for host discovery line
        if line.contains("Nmap scan report for") {
            if let Some(ip) = line.split("for ").nth(1) {
                let clean_ip = ip.trim().split_whitespace().next().unwrap_or(ip.trim()).to_string();
                self.current_host = Some(clean_ip.clone());
                // Don't create observation yet - wait for status information
                return None;
            }
        }
        
        // Check for host status lines
        else if line.contains("Host is up") || line.contains("Host is down") {
            if let Some(ref current_ip) = self.current_host {
                let status = if line.contains("Host is up") { "up" } else { "down" };
                
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
                                    let latency_info = &line[latency_start+1..latency_end];
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
            if let Some(ref current_ip) = self.current_host {
                if let Some(mac_info) = self.parse_mac_address(line) {
                    return Some(Observation {
                        scan_id: self.scan_id,
                        kind: ObservationKind::Host,
                        fields: {
                            let mut fields = serde_json::Map::new();
                            fields.insert("ip".to_string(), current_ip.clone().into());
                            fields.insert("mac_address".to_string(), mac_info.mac.into());
                            if let Some(vendor) = mac_info.vendor {
                                fields.insert("vendor".to_string(), vendor.into());
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
        else if line.contains("OS details:") || line.contains("Running:") || line.contains("OS CPE:") || line.contains("Aggressive OS guesses:") {
            if let Some(ref current_ip) = self.current_host {
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
        else if line.contains("rDNS record for") || (self.current_host.is_some() && line.contains(".") && !line.contains("/") && !line.contains("open")) {
            if let Some(ref current_ip) = self.current_host {
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
                                        fields.insert("version".to_string(), version_info.join(" ").into());
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
        else if line.contains("Scanning") || line.contains("Completed") || line.contains("Initiating") {
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
        }
        
        // For lines that don't match specific patterns, create raw output metric
        Some(Observation {
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
        })
    }

    /// Parse MAC address lines from nmap output
    fn parse_mac_address(&self, line: &str) -> Option<MacInfo> {
        // Parse "MAC Address: 00:11:22:33:44:55 (Vendor Name)"
        // Also handle formats like "MAC Address: XX:XX:XX:XX:XX:XX (Unknown)"
        let mac_regex = Regex::new(r"MAC Address:\s+([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})(?:\s+\(([^)]+)\))?").unwrap();
        
        if let Some(captures) = mac_regex.captures(line) {
            let mac = captures.get(1)?.as_str().to_string();
            let vendor = captures.get(2)
                .map(|m| m.as_str().to_string())
                .filter(|v| !v.is_empty() && v != "Unknown" && v != "unknown");
            
            return Some(MacInfo { mac, vendor });
        }
        
        None
    }

    /// Parse OS detection information from nmap output
    fn parse_os_detection(&self, line: &str) -> Option<OsInfo> {
        // Handle different OS detection formats from nmap
        
        // "OS details: Linux 3.2 - 4.9"
        if line.starts_with("OS details:") {
            let details = line.strip_prefix("OS details:")?.trim().to_string();
            let (family, version) = self.extract_os_family_and_version(&details);
            return Some(OsInfo {
                name: Some(details.clone()),
                family: Some(family),
                version,
                accuracy: None,
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
                    let percent_str = &guess_info[paren_start+1..paren_end];
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
    fn extract_os_family_and_version(&self, os_desc: &str) -> (String, Option<String>) {
        let lower_desc = os_desc.to_lowercase();
        
        // Detect common OS families
        let family = if lower_desc.contains("linux") {
            "Linux".to_string()
        } else if lower_desc.contains("windows") {
            "Windows".to_string()
        } else if lower_desc.contains("macos") || lower_desc.contains("mac os") || lower_desc.contains("darwin") {
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
    fn extract_version_from_description(&self, desc: &str) -> Option<String> {
        // Pattern for version numbers like "3.2", "4.9", "10.15", etc.
        let version_regex = Regex::new(r"(\d+(?:\.\d+)*(?:\.\w+)?)").unwrap();
        
        // Look for common version patterns
        if let Some(captures) = version_regex.captures(desc) {
            return Some(captures.get(1)?.as_str().to_string());
        }
        
        None
    }

    /// Parse CPE (Common Platform Enumeration) strings
    fn parse_cpe_string(&self, cpe: &str) -> Option<OsInfo> {
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
    fn vendor_to_family(&self, vendor: &str) -> String {
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
    fn parse_hostname(&self, line: &str) -> Option<String> {
        // "rDNS record for 192.168.1.1: hostname.domain.com"
        if line.contains("rDNS record for") {
            if let Some(colon_pos) = line.find(':') {
                let hostname = line[colon_pos+1..].trim();
                if !hostname.is_empty() && hostname != "N/A" {
                    return Some(hostname.to_string());
                }
            }
        }
        
        // Also try to extract from "Nmap scan report for hostname (ip)" format
        if line.contains("Nmap scan report for") && line.contains('(') {
            if let Some(for_pos) = line.find("for ") {
                if let Some(paren_pos) = line.find('(') {
                    let hostname = line[for_pos+4..paren_pos].trim();
                    // Make sure it's not just an IP address
                    if hostname.contains('.') && !hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        return Some(hostname.to_string());
                    }
                }
            }
        }
        
        None
    }

    /// Parse masscan-style "Discovered open port" lines
    fn parse_discovered_port_line(&self, line: &str) -> Option<DiscoveredPort> {
        // "Discovered open port 80/tcp on 192.168.1.1"
        if let Some(port_start) = line.find("port ") {
            let after_port = &line[port_start + 5..];
            if let Some(on_pos) = after_port.find(" on ") {
                let port_proto = &after_port[..on_pos];
                let ip_part = &after_port[on_pos + 4..];
                
                if let Some(slash_pos) = port_proto.find('/') {
                    let port = &port_proto[..slash_pos];
                    let protocol = &port_proto[slash_pos + 1..];
                    let ip = ip_part.trim().split_whitespace().next().unwrap_or(ip_part.trim());
                    
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
    pub fn current_host(&self) -> Option<&String> {
        self.current_host.as_ref()
    }
}

#[derive(Debug)]
struct DiscoveredPort {
    ip: String,
    port: String,
    protocol: String,
}