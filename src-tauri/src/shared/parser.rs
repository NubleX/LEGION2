// Add these dependencies to Cargo.toml:
// [dependencies]
// roxmltree = "0.18"
// serde = { version = "1.0", features = ["derive"] }
// chrono = { version = "0.4", features = ["serde"] }
// anyhow = "1.0"
// thiserror = "1.0"
// tracing = "0.1"

use anyhow::Result;
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("Malformed XML document: {0}")]
    MalformedXml(#[from] roxmltree::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Missing required element: {0}")]
    MissingElement(String),
}

#[derive(Debug)]
pub struct Parser {
    xml_content: String,
    session: Session,
    hosts: HashMap<String, Host>,
}

impl Parser {
    pub fn new(xml_content: &str) -> Result<Self, ParserError> {
        info!("Parsing Nmap XML report");

        // Parse the XML document
        let document = Document::parse(xml_content).map_err(ParserError::MalformedXml)?;

        // Parse session information
        let session = Session::from_document(&document)?;

        // Parse all hosts
        let mut hosts = HashMap::new();

        // Find all host elements
        for host_node in document
            .descendants()
            .filter(|n| n.tag_name().name() == "host")
        {
            let host = Host::from_xml_node(&host_node)
                .map_err(|e| ParserError::ParseError(format!("Failed to parse host: {}", e)))?;

            let ip = host.get_ip().to_string();
            if !ip.is_empty() {
                hosts.insert(ip.clone(), host);
            }
        }

        debug!("Parsed {} hosts from Nmap report", hosts.len());

        Ok(Parser {
            xml_content: xml_content.to_string(),
            session,
            hosts,
        })
    }

    pub fn get_session(&self) -> &Session {
        &self.session
    }

    pub fn get_host(&self, ip_addr: &str) -> Option<&Host> {
        self.hosts.get(ip_addr)
    }

    pub fn get_all_hosts(&self, status: Option<&str>) -> Vec<&Host> {
        match status {
            None => self.hosts.values().collect(),
            Some(status_filter) => self
                .hosts
                .values()
                .filter(|host| host.status == status_filter)
                .collect(),
        }
    }

    pub fn get_all_ips(&self, status: Option<&str>) -> Vec<String> {
        match status {
            None => self.hosts.keys().cloned().collect(),
            Some(status_filter) => self
                .hosts
                .iter()
                .filter(|(_, host)| host.status == status_filter)
                .map(|(ip, _)| ip.clone())
                .collect(),
        }
    }

    pub fn get_hosts_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn get_hosts_by_vendor(&self, vendor: &str) -> Vec<&Host> {
        self.hosts
            .values()
            .filter(|host| host.vendor.to_lowercase().contains(&vendor.to_lowercase()))
            .collect()
    }

    pub fn get_hosts_with_open_ports(&self) -> Vec<&Host> {
        let document = match Document::parse(&self.xml_content) {
            Ok(doc) => doc,
            Err(_) => return vec![],
        };

        self.hosts
            .values()
            .filter(|host| {
                // We need to find the host node in the document to check ports
                document
                    .descendants()
                    .find(|n| {
                        n.tag_name().name() == "host"
                            && n.descendants()
                                .find(|addr| {
                                    addr.tag_name().name() == "address"
                                        && addr.attribute("addr").unwrap_or("") == host.get_ip()
                                })
                                .is_some()
                    })
                    .map(|host_node| host.has_open_ports(&host_node))
                    .unwrap_or(false)
            })
            .collect()
    }

    pub fn get_unique_vendors(&self) -> Vec<String> {
        let mut vendors: Vec<String> = self
            .hosts
            .values()
            .map(|host| host.vendor.clone())
            .filter(|vendor| !vendor.is_empty())
            .collect();

        vendors.sort();
        vendors.dedup();
        vendors
    }

    pub fn get_hosts_with_service(&self, service_name: &str) -> Vec<&Host> {
        let document = match Document::parse(&self.xml_content) {
            Ok(doc) => doc,
            Err(_) => return vec![],
        };

        self.hosts
            .values()
            .filter(|host| {
                document
                    .descendants()
                    .find(|n| {
                        n.tag_name().name() == "host"
                            && n.descendants()
                                .find(|addr| {
                                    addr.tag_name().name() == "address"
                                        && addr.attribute("addr").unwrap_or("") == host.get_ip()
                                })
                                .is_some()
                    })
                    .map(|host_node| {
                        host_node
                            .descendants()
                            .filter(|n| n.tag_name().name() == "service")
                            .any(|service_node| {
                                service_node
                                    .attribute("name")
                                    .map(|name| name.contains(service_name))
                                    .unwrap_or(false)
                            })
                    })
                    .unwrap_or(false)
            })
            .collect()
    }
}

// Session struct (replicating the Python Session class)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    pub finish_time: String,
    pub nmap_version: String,
    pub scan_args: String,
    pub start_time: String,
    pub total_hosts: String,
    pub up_hosts: String,
    pub down_hosts: String,
    pub scan_type: String,
    pub protocol: String,
    pub num_services: String,
}

impl Session {
    pub fn from_document(doc: &Document) -> Result<Self, ParserError> {
        // Get nmaprun node
        let nmaprun_node = doc
            .root()
            .first_child()
            .ok_or_else(|| ParserError::MissingElement("nmaprun".to_string()))?;

        if nmaprun_node.tag_name().name() != "nmaprun" {
            return Err(ParserError::ParseError(
                "Root element is not nmaprun".to_string(),
            ));
        }

        // Get finish time
        let finish_time = doc
            .descendants()
            .find(|n| n.tag_name().name() == "finished")
            .and_then(|n| n.attribute("timestr"))
            .unwrap_or("")
            .to_string();

        // Get nmap version and scan args
        let nmap_version = nmaprun_node.attribute("version").unwrap_or("").to_string();
        let scan_args = nmaprun_node.attribute("args").unwrap_or("").to_string();
        let start_time = nmaprun_node.attribute("startstr").unwrap_or("").to_string();

        // Get scan info
        let mut scan_type = String::new();
        let mut protocol = String::new();
        let mut num_services = String::new();

        if let Some(scaninfo_node) = doc
            .descendants()
            .find(|n| n.tag_name().name() == "scaninfo")
        {
            scan_type = scaninfo_node.attribute("type").unwrap_or("").to_string();
            protocol = scaninfo_node
                .attribute("protocol")
                .unwrap_or("")
                .to_string();
            num_services = scaninfo_node
                .attribute("numservices")
                .unwrap_or("")
                .to_string();
        }

        // Get hosts stats
        let hosts_node = doc
            .descendants()
            .find(|n| n.tag_name().name() == "hosts")
            .ok_or_else(|| ParserError::MissingElement("hosts".to_string()))?;

        let total_hosts = hosts_node.attribute("total").unwrap_or("0").to_string();
        let up_hosts = hosts_node.attribute("up").unwrap_or("0").to_string();
        let down_hosts = hosts_node.attribute("down").unwrap_or("0").to_string();

        Ok(Session {
            finish_time,
            nmap_version,
            scan_args,
            start_time,
            total_hosts,
            up_hosts,
            down_hosts,
            scan_type,
            protocol,
            num_services,
        })
    }

    pub fn hosts_up_percentage(&self) -> f64 {
        if let (Ok(total), Ok(up)) = (
            self.total_hosts.parse::<f64>(),
            self.up_hosts.parse::<f64>(),
        ) {
            if total > 0.0 {
                (up / total) * 100.0
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    pub fn scan_summary(&self) -> String {
        format!(
            "Nmap {} scan completed. {} hosts up ({:.1}%) out of {} total hosts.",
            self.nmap_version,
            self.up_hosts,
            self.hosts_up_percentage(),
            self.total_hosts
        )
    }
}

// Host struct (replicating the Python Host class)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub ipv4: String,
    pub ipv6: String,
    pub macaddr: String,
    pub status: String,
    pub hostname: String,
    pub vendor: String,
    pub uptime: String,
    pub lastboot: String,
    pub distance: u32,
    pub state: String,
    pub count: String,
}

impl Host {
    pub fn from_xml_node(host_node: &roxmltree::Node) -> Result<Self, Box<dyn std::error::Error>> {
        let mut ipv4 = String::new();
        let mut ipv6 = String::new();
        let mut macaddr = String::new();
        let mut vendor = String::new();
        let mut hostname = String::new();
        let mut uptime = String::new();
        let mut lastboot = String::new();
        let mut distance = 0u32;
        let mut state = String::new();
        let mut count = String::new();
        let mut status = String::new();

        // Parse status
        if let Some(status_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "status")
        {
            status = status_node.attribute("state").unwrap_or("").to_string();
        }

        // Parse addresses
        for addr_node in host_node
            .children()
            .filter(|n| n.tag_name().name() == "address")
        {
            let addr_type = addr_node.attribute("addrtype").unwrap_or("");
            let addr = addr_node.attribute("addr").unwrap_or("");

            match addr_type {
                "ipv4" => ipv4 = addr.to_string(),
                "ipv6" => ipv6 = addr.to_string(),
                "mac" => {
                    macaddr = addr.to_string();
                    vendor = addr_node.attribute("vendor").unwrap_or("").to_string();
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
            hostname = hostname_node.attribute("name").unwrap_or("").to_string();
        }

        // Parse uptime
        if let Some(uptime_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "uptime")
        {
            uptime = uptime_node.attribute("seconds").unwrap_or("").to_string();
            lastboot = uptime_node.attribute("lastboot").unwrap_or("").to_string();
        }

        // Parse distance
        if let Some(distance_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "distance")
        {
            distance = distance_node
                .attribute("value")
                .unwrap_or("0")
                .parse()
                .unwrap_or(0);
        }

        // Parse extraports
        if let Some(extraports_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "extraports")
        {
            state = extraports_node.attribute("state").unwrap_or("").to_string();
            count = extraports_node.attribute("count").unwrap_or("").to_string();
        }

        Ok(Host {
            ipv4,
            ipv6,
            macaddr,
            status,
            hostname,
            vendor,
            uptime,
            lastboot,
            distance,
            state,
            count,
        })
    }

    pub fn get_ip(&self) -> &str {
        if !self.ipv4.is_empty() {
            &self.ipv4
        } else if !self.ipv6.is_empty() {
            &self.ipv6
        } else {
            ""
        }
    }

    pub fn is_up(&self) -> bool {
        self.status == "up"
    }

    pub fn has_open_ports(&self, host_node: &roxmltree::Node) -> bool {
        host_node
            .children()
            .filter(|n| n.tag_name().name() == "port")
            .any(|port_node| {
                port_node
                    .children()
                    .find(|n| n.tag_name().name() == "state")
                    .and_then(|state_node| state_node.attribute("state"))
                    .map(|state| state == "open")
                    .unwrap_or(false)
            })
    }
}

// Main parsing functions
pub fn parse_nmap_report(file_path: &str) -> Result<Parser, ParserError> {
    info!("Parsing Nmap report from file: {}", file_path);

    let content = fs::read_to_string(file_path).map_err(ParserError::IoError)?;

    Parser::new(&content)
}

pub fn parse_nmap_content(xml_content: &str) -> Result<Parser, ParserError> {
    info!("Parsing Nmap report from content");
    Parser::new(xml_content)
}

// Utility functions for working with parsed data
pub fn filter_hosts_by_os_family<'a>(hosts: &'a [&'a Host], _os_family: &str) -> Vec<&'a Host> {
    // This would require access to OS information from the host nodes
    // Implementation would depend on how OS data is stored
    hosts.iter().filter(|_| false).cloned().collect() // Placeholder
}

pub fn get_hosts_with_vulnerabilities<'a>(parser: &'a Parser) -> Vec<&'a Host> {
    // This would check for vulnerability information in the report
    parser.hosts.values().filter(|_| false).collect() // Placeholder
}
