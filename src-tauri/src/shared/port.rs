// Add these dependencies to Cargo.toml:
// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// roxmltree = "0.18"
// tracing = "0.1"
// anyhow = "1.0"
// thiserror = "1.0"

use anyhow::Result;
use roxmltree::Node;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Port {
    pub port_id: String,
    pub protocol: String,
    pub state: String,
    pub state_reason: String,
    pub state_reason_ttl: u32,
    pub service: Option<Service>,
    pub scripts: Vec<Script>,
    pub cpe: Vec<String>,
    #[serde(skip)]
    port_node: Option<Node<'static, 'static>>, // For lazy parsing if needed
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Service {
    pub name: String,
    pub product: String,
    pub version: String,
    pub extrainfo: String,
    pub ostype: String,
    pub method: String,
    pub conf: String,
    pub servicefp: String,
    pub tunnel: String,
    pub proto: String,
    pub rpcnum: String,
    pub lowver: String,
    pub cpe: Vec<String>,
    pub devicetype: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Script {
    pub id: String,
    pub output: String,
    pub elements: HashMap<String, String>,
}

impl Service {
    pub fn from_xml_node(node: &Node) -> Self {
        Self {
            name: node.attribute("name").unwrap_or("").to_string(),
            product: node.attribute("product").unwrap_or("").to_string(),
            version: node.attribute("version").unwrap_or("").to_string(),
            extrainfo: node.attribute("extrainfo").unwrap_or("").to_string(),
            ostype: node.attribute("ostype").unwrap_or("").to_string(),
            method: node.attribute("method").unwrap_or("").to_string(),
            conf: node.attribute("conf").unwrap_or("").to_string(),
            servicefp: node.attribute("servicefp").unwrap_or("").to_string(),
            tunnel: node.attribute("tunnel").unwrap_or("").to_string(),
            proto: node.attribute("proto").unwrap_or("").to_string(),
            rpcnum: node.attribute("rpcnum").unwrap_or("").to_string(),
            lowver: node.attribute("lowver").unwrap_or("").to_string(),
            cpe: node
                .children()
                .filter(|n| n.tag_name().name() == "cpe")
                .filter_map(|n| n.text())
                .map(|s| s.to_string())
                .collect(),
            devicetype: node.attribute("devicetype").unwrap_or("").to_string(),
            hostname: node.attribute("hostname").unwrap_or("").to_string(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.product.is_empty() && self.version.is_empty()
    }

    pub fn get_banner(&self) -> String {
        if !self.servicefp.is_empty() {
            return self.servicefp.clone();
        }

        if !self.product.is_empty() {
            if !self.version.is_empty() {
                return format!("{} {}", self.product, self.version);
            }
            return self.product.clone();
        }

        self.name.clone()
    }

    pub fn is_vulnerable(&self) -> bool {
        // Simple heuristic - in practice you'd check against vulnerability databases
        !self.extrainfo.to_lowercase().contains("vuln")
            && !self.product.to_lowercase().contains("vuln")
    }
}

impl Script {
    pub fn from_xml_node(node: &Node) -> Self {
        let mut elements = HashMap::new();

        // Parse script elements
        for child in node.children() {
            if child.is_element() && child.tag_name().name() == "elem" {
                if let Some(key) = child.attribute("key") {
                    elements.insert(key.to_string(), child.text().unwrap_or("").to_string());
                }
            }
        }

        Self {
            id: node.attribute("id").unwrap_or("").to_string(),
            output: node
                .attribute("output")
                .unwrap_or(node.text().unwrap_or(""))
                .to_string(),
            elements,
        }
    }

    pub fn is_vulnerable(&self) -> bool {
        // Check for common vulnerability indicators in script output
        let vuln_indicators = ["vuln", "cve", "exploit", "vulnerable", "risk"];
        let output_lower = self.output.to_lowercase();

        vuln_indicators
            .iter()
            .any(|&indicator| output_lower.contains(indicator))
    }

    pub fn get_cve_ids(&self) -> Vec<String> {
        // Extract CVE IDs from script output using regex
        use regex::Regex;
        let re = Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap();
        re.find_iter(&self.output)
            .map(|m| m.as_str().to_string())
            .collect()
    }
}

impl Port {
    pub fn from_xml_node(port_node: &Node) -> Result<Self> {
        // Parse port attributes
        let port_id = port_node.attribute("portid").unwrap_or("").to_string();
        let protocol = port_node.attribute("protocol").unwrap_or("").to_string();

        // Parse state information
        let (state, state_reason, state_reason_ttl) = if let Some(state_node) = port_node
            .children()
            .find(|n| n.tag_name().name() == "state")
        {
            (
                state_node.attribute("state").unwrap_or("").to_string(),
                state_node.attribute("reason").unwrap_or("").to_string(),
                state_node
                    .attribute("reason_ttl")
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0),
            )
        } else {
            (String::new(), String::new(), 0)
        };

        // Parse service information
        let service = port_node
            .children()
            .find(|n| n.tag_name().name() == "service")
            .map(|service_node| Service::from_xml_node(&service_node));

        // Parse scripts
        let scripts: Vec<Script> = port_node
            .children()
            .filter(|n| n.tag_name().name() == "script")
            .map(|script_node| Script::from_xml_node(&script_node))
            .collect();

        // Parse CPEs
        let cpe: Vec<String> = port_node
            .children()
            .filter(|n| n.tag_name().name() == "cpe")
            .filter_map(|n| n.text())
            .map(|s| s.to_string())
            .collect();

        Ok(Port {
            port_id,
            protocol,
            state,
            state_reason,
            state_reason_ttl,
            service,
            scripts,
            cpe,
            port_node: None, // We don't store the node in this implementation
        })
    }

    pub fn get_service(&self) -> Option<&Service> {
        self.service.as_ref()
    }

    pub fn get_scripts(&self) -> &[Script] {
        &self.scripts
    }

    pub fn get_cpe(&self) -> &[String] {
        &self.cpe
    }

    pub fn is_open(&self) -> bool {
        self.state == "open"
    }

    pub fn is_filtered(&self) -> bool {
        self.state == "filtered"
    }

    pub fn is_closed(&self) -> bool {
        self.state == "closed"
    }

    pub fn get_state(&self) -> &str {
        &self.state
    }

    pub fn get_protocol(&self) -> &str {
        &self.protocol
    }

    pub fn get_port_id(&self) -> &str {
        &self.port_id
    }

    pub fn get_port_number(&self) -> Option<u16> {
        self.port_id.parse().ok()
    }

    pub fn has_service(&self) -> bool {
        self.service.is_some()
    }

    pub fn has_vuln_scripts(&self) -> bool {
        self.scripts.iter().any(|s| s.is_vulnerable())
    }

    pub fn get_vuln_scripts(&self) -> Vec<&Script> {
        self.scripts.iter().filter(|s| s.is_vulnerable()).collect()
    }

    pub fn get_banner(&self) -> String {
        if let Some(service) = &self.service {
            service.get_banner()
        } else {
            format!("{} port {}", self.protocol, self.port_id)
        }
    }

    pub fn is_common_service(&self) -> bool {
        let common_ports = [
            "21", "22", "23", "25", "53", "80", "110", "111", "135", "139", "143", "443", "445",
            "993", "995", "1723", "3306", "3389", "5900", "8080",
        ];
        common_ports.contains(&self.port_id.as_str())
    }

    pub fn get_service_name(&self) -> String {
        if let Some(service) = &self.service {
            if !service.name.is_empty() {
                return service.name.clone();
            }
        }
        self.port_id.clone()
    }

    pub fn get_version_info(&self) -> Option<String> {
        self.service.as_ref().and_then(|s| {
            if !s.product.is_empty() {
                if !s.version.is_empty() {
                    Some(format!("{} {}", s.product, s.version))
                } else {
                    Some(s.product.clone())
                }
            } else if !s.version.is_empty() {
                Some(s.version.clone())
            } else {
                None
            }
        })
    }
}

// Port collection and management
pub struct PortCollection {
    ports: Vec<Port>,
}

impl PortCollection {
    pub fn new() -> Self {
        Self { ports: Vec::new() }
    }

    pub fn from_xml_nodes(port_nodes: &[Node]) -> Result<Self> {
        let mut ports = Vec::new();

        for port_node in port_nodes {
            match Port::from_xml_node(port_node) {
                Ok(port) => ports.push(port),
                Err(e) => {
                    debug!("Failed to parse port: {}", e);
                    continue;
                }
            }
        }

        Ok(Self { ports })
    }

    pub fn add_port(&mut self, port: Port) {
        self.ports.push(port);
    }

    pub fn get_ports(&self) -> &[Port] {
        &self.ports
    }

    pub fn get_open_ports(&self) -> Vec<&Port> {
        self.ports.iter().filter(|p| p.is_open()).collect()
    }

    pub fn get_filtered_ports(&self) -> Vec<&Port> {
        self.ports.iter().filter(|p| p.is_filtered()).collect()
    }

    pub fn get_ports_by_protocol(&self, protocol: &str) -> Vec<&Port> {
        self.ports
            .iter()
            .filter(|p| p.protocol == protocol)
            .collect()
    }

    pub fn get_port_by_id(&self, port_id: &str) -> Option<&Port> {
        self.ports.iter().find(|p| p.port_id == port_id)
    }

    pub fn get_ports_with_services(&self) -> Vec<&Port> {
        self.ports.iter().filter(|p| p.has_service()).collect()
    }

    pub fn get_ports_with_vulns(&self) -> Vec<&Port> {
        self.ports.iter().filter(|p| p.has_vuln_scripts()).collect()
    }

    pub fn get_ports_by_service_name(&self, service_name: &str) -> Vec<&Port> {
        self.ports
            .iter()
            .filter(|p| {
                if let Some(service) = &p.service {
                    service.name == service_name
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn count_open_ports(&self) -> usize {
        self.ports.iter().filter(|p| p.is_open()).count()
    }

    pub fn count_filtered_ports(&self) -> usize {
        self.ports.iter().filter(|p| p.is_filtered()).count()
    }

    pub fn count_closed_ports(&self) -> usize {
        self.ports.iter().filter(|p| p.is_closed()).count()
    }

    pub fn get_unique_services(&self) -> Vec<String> {
        let mut services: Vec<String> = self
            .ports
            .iter()
            .filter_map(|p| {
                p.service.as_ref().and_then(|s| {
                    if !s.name.is_empty() {
                        Some(s.name.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        services.sort();
        services.dedup();
        services
    }

    pub fn get_top_ports(&self, count: usize) -> Vec<&Port> {
        self.ports.iter().take(count).collect()
    }
}

// Port scanning utilities
pub struct PortScanner;

impl PortScanner {
    pub fn is_port_common(port: u16) -> bool {
        matches!(
            port,
            21 | 22
                | 23
                | 25
                | 53
                | 80
                | 110
                | 111
                | 135
                | 139
                | 143
                | 443
                | 445
                | 993
                | 995
                | 1723
                | 3306
                | 3389
                | 5900
                | 8080
        )
    }

    pub fn get_service_name(port: u16) -> &'static str {
        match port {
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            80 => "http",
            110 => "pop3",
            143 => "imap",
            443 => "https",
            445 => "smb",
            993 => "imaps",
            995 => "pop3s",
            3306 => "mysql",
            3389 => "rdp",
            5900 => "vnc",
            8080 => "http-proxy",
            _ => "unknown",
        }
    }

    pub fn get_port_risk(port: u16) -> u8 {
        match port {
            21 | 23 | 25 | 111 | 135 | 139 | 445 => 9, // High risk
            22 | 80 | 443 | 3306 | 3389 => 7,          // Medium-high risk
            110 | 143 | 993 | 995 => 5,                // Medium risk
            53 | 8080 => 3,                            // Low-medium risk
            _ => 1,                                    // Low risk
        }
    }
}
