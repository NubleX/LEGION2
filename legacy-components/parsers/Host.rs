// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// serde_xml_rs = "0.6"
// roxmltree = "0.18"
// tracing = "0.1"
// anyhow = "1.0"
// thiserror = "1.0"

use anyhow::{Context, Result};
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

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
    #[serde(skip)]
    host_node: Option<Document>, // Store for lazy parsing
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Script {
    pub id: String,
    pub output: String,
    pub host_id: String,
    pub elements: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Port {
    pub portid: String,
    pub protocol: String,
    pub state: String,
    pub state_reason: String,
    pub service: Option<Service>,
}

impl Service {
    pub fn from_xml_node(node: &roxmltree::Node) -> Self {
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
        }
    }
}

impl Script {
    pub fn from_xml_node(node: &roxmltree::Node, host_id: &str) -> Self {
        let mut elements = HashMap::new();

        // Parse script elements if they exist
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
            host_id: host_id.to_string(),
            elements,
        }
    }
}

impl Port {
    pub fn from_xml_node(node: &roxmltree::Node) -> Self {
        let service = node
            .children()
            .find(|n| n.tag_name().name() == "service")
            .map(|service_node| Service::from_xml_node(&service_node));

        let state_node = node.children().find(|n| n.tag_name().name() == "state");

        Self {
            portid: node.attribute("portid").unwrap_or("").to_string(),
            protocol: node.attribute("protocol").unwrap_or("").to_string(),
            state: state_node
                .and_then(|n| n.attribute("state"))
                .unwrap_or("")
                .to_string(),
            state_reason: state_node
                .and_then(|n| n.attribute("reason"))
                .unwrap_or("")
                .to_string(),
            service,
        }
    }
}

impl Host {
    pub fn from_xml_node(host_node: &roxmltree::Node) -> Result<Self> {
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
            host_node: None, // We don't store the node in this implementation
        })
    }

    pub fn get_os(&self, host_node: &roxmltree::Node) -> Vec<OS> {
        let mut oss = Vec::new();

        // Parse osclass elements
        for osclass_node in host_node
            .children()
            .filter(|n| n.tag_name().name() == "osclass")
        {
            oss.push(OS::from_xml_node(&osclass_node));
        }

        // Parse osmatch elements
        for osmatch_node in host_node
            .children()
            .filter(|n| n.tag_name().name() == "osmatch")
        {
            oss.push(OS::from_osmatch_node(&osmatch_node));
        }

        oss
    }

    pub fn all_ports(&self, host_node: &roxmltree::Node) -> Vec<Port> {
        host_node
            .children()
            .filter(|n| n.tag_name().name() == "port")
            .map(|port_node| Port::from_xml_node(&port_node))
            .collect()
    }

    pub fn get_ports(
        &self,
        host_node: &roxmltree::Node,
        protocol: &str,
        state: &str,
    ) -> Vec<String> {
        host_node
            .children()
            .filter(|n| n.tag_name().name() == "port")
            .filter(|port_node| {
                port_node.attribute("protocol").unwrap_or("") == protocol
                    && port_node
                        .children()
                        .find(|n| n.tag_name().name() == "state")
                        .and_then(|state_node| state_node.attribute("state"))
                        .unwrap_or("")
                        == state
            })
            .filter_map(|port_node| port_node.attribute("portid").map(|s| s.to_string()))
            .collect()
    }

    pub fn get_scripts(&self, host_node: &roxmltree::Node) -> Vec<Script> {
        host_node
            .children()
            .filter(|n| n.tag_name().name() == "hostscript")
            .flat_map(|hostscript_node| {
                hostscript_node
                    .children()
                    .filter(|n| n.tag_name().name() == "script")
                    .map(|script_node| Script::from_xml_node(&script_node, &self.ipv4))
                    .collect::<Vec<Script>>()
            })
            .collect()
    }

    pub fn get_host_scripts(&self, host_node: &roxmltree::Node) -> Vec<Script> {
        host_node
            .children()
            .filter(|n| n.tag_name().name() == "script")
            .map(|script_node| Script::from_xml_node(&script_node, &self.ipv4))
            .collect()
    }

    pub fn get_service(
        &self,
        host_node: &roxmltree::Node,
        protocol: &str,
        port: &str,
    ) -> Option<Service> {
        host_node
            .children()
            .filter(|n| n.tag_name().name() == "port")
            .find(|port_node| {
                port_node.attribute("protocol").unwrap_or("") == protocol
                    && port_node.attribute("portid").unwrap_or("") == port
            })
            .and_then(|port_node| {
                port_node
                    .children()
                    .find(|n| n.tag_name().name() == "service")
                    .map(|service_node| Service::from_xml_node(&service_node))
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
        !self.get_ports(host_node, "tcp", "open").is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OS {
    pub name: String,
    pub family: String,
    pub generation: String,
    pub os_type: String,
    pub vendor: String,
    pub accuracy: u8,
    pub cpe: Vec<String>,
}

impl OS {
    pub fn from_xml_node(node: &roxmltree::Node) -> Self {
        Self {
            name: node.attribute("osfamily").unwrap_or("").to_string(),
            family: node.attribute("osfamily").unwrap_or("").to_string(),
            generation: node.attribute("osgen").unwrap_or("").to_string(),
            os_type: node.attribute("type").unwrap_or("").to_string(),
            vendor: node.attribute("vendor").unwrap_or("").to_string(),
            accuracy: node
                .attribute("accuracy")
                .unwrap_or("0")
                .parse()
                .unwrap_or(0),
            cpe: node
                .children()
                .filter(|n| n.tag_name().name() == "cpe")
                .map(|n| n.text().unwrap_or("").to_string())
                .collect(),
        }
    }

    pub fn from_osmatch_node(node: &roxmltree::Node) -> Self {
        Self {
            name: node.attribute("name").unwrap_or("").to_string(),
            family: String::new(),
            generation: String::new(),
            os_type: String::new(),
            vendor: String::new(),
            accuracy: node
                .attribute("accuracy")
                .unwrap_or("0")
                .parse()
                .unwrap_or(0),
            cpe: Vec::new(),
        }
    }
}

// Host parser that processes entire Nmap XML output
pub struct HostParser;

impl HostParser {
    pub fn parse_nmap_xml(xml_content: &str) -> Result<Vec<Host>> {
        let doc = Document::parse(xml_content).context("Failed to parse XML document")?;

        let mut hosts = Vec::new();

        // Find all host elements
        for host_node in doc.descendants().filter(|n| n.tag_name().name() == "host") {
            match Host::from_xml_node(&host_node) {
                Ok(host) => hosts.push(host),
                Err(e) => {
                    debug!("Failed to parse host: {}", e);
                    continue;
                }
            }
        }

        Ok(hosts)
    }

    pub fn parse_nmap_file(file_path: &str) -> Result<Vec<Host>> {
        let content = std::fs::read_to_string(file_path).context("Failed to read Nmap XML file")?;

        Self::parse_nmap_xml(&content)
    }
}

// Utility functions for working with hosts
pub fn filter_hosts_by_status(hosts: &[Host], status: &str) -> Vec<&Host> {
    hosts.iter().filter(|h| h.status == status).collect()
}

pub fn filter_hosts_with_open_ports(
    hosts: &[Host],
    host_nodes: &[roxmltree::Node],
) -> Vec<(&Host, &roxmltree::Node)> {
    hosts
        .iter()
        .zip(host_nodes.iter())
        .filter(|(host, node)| host.has_open_ports(node))
        .collect()
}

pub fn get_unique_vendors(hosts: &[Host]) -> Vec<String> {
    let mut vendors: Vec<String> = hosts
        .iter()
        .map(|h| h.vendor.clone())
        .filter(|v| !v.is_empty())
        .collect();

    vendors.sort();
    vendors.dedup();
    vendors
}
