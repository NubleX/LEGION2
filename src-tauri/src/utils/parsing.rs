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
                if let Some(mac_info) = self.parse_mac_address_line(line) {
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
    fn parse_mac_address_line(&self, line: &str) -> Option<MacInfo> {
        // Parse "MAC Address: 00:11:22:33:44:55 (Vendor Name)"
        let mac_regex = Regex::new(r"MAC Address:\s+([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})(?:\s+\(([^)]+)\))?").unwrap();
        
        if let Some(captures) = mac_regex.captures(line) {
            let mac = captures.get(1)?.as_str().to_string();
            let vendor = captures.get(2).map(|m| m.as_str().to_string());
            
            return Some(MacInfo { mac, vendor });
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