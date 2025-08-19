// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::shared::shared::{Observation, ObservationKind};
use anyhow::Result;
use roxmltree::Document;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// Generic XML parser for various scan outputs (nmap, masscan, etc.)
pub struct XmlParser {
    scan_id: Uuid,
}

/// Host information extracted from XML (based on legacy Host.rs)
#[derive(Debug, Clone)]
pub struct XmlHost {
    pub ipv4: String,
    pub ipv6: String,
    pub mac_address: String,
    pub status: String,
    pub hostname: String,
    pub vendor: String,
    pub uptime: String,
    pub lastboot: String,
    pub distance: u32,
    pub os_name: Option<String>,
    pub os_family: Option<String>,
    pub os_accuracy: Option<f32>,
    pub extraports_state: String,
    pub extraports_count: String,
}

/// Service information extracted from XML (based on legacy Service.rs)
#[derive(Debug, Clone)]
pub struct XmlService {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service_name: String,
    pub product: String,
    pub version: String,
    pub extrainfo: String,
    pub banner: String,
    pub confidence: u8,
    pub cpe: Vec<String>,
}

/// Script information extracted from XML (based on legacy Script.rs)
#[derive(Debug, Clone)]
pub struct XmlScript {
    pub id: String,
    pub output: String,
    pub elements: HashMap<String, String>,
    pub cve_ids: Vec<String>,
}

/// Session information extracted from XML (based on legacy Session.rs)
#[derive(Debug, Clone)]
pub struct XmlSession {
    pub nmap_version: String,
    pub scan_args: String,
    pub start_time: String,
    pub finish_time: String,
    pub total_hosts: u32,
    pub up_hosts: u32,
    pub down_hosts: u32,
    pub scan_type: String,
    pub protocol: String,
    pub num_services: u32,
}

impl XmlParser {
    pub fn new(scan_id: Uuid) -> Self {
        Self { scan_id }
    }

    /// Parse nmap XML file and return comprehensive observations
    pub fn parse_nmap_xml(&self, xml_path: &Path) -> Result<Vec<Observation>> {
        let xml_content = std::fs::read_to_string(xml_path)?;
        let doc = Document::parse(&xml_content)?;
        let mut observations = Vec::new();

        // Parse session information first
        if let Ok(session_obs) = self.create_session_observation(&doc) {
            observations.push(session_obs);
        }

        // Parse hosts using the legacy Host.rs logic
        for host_node in doc.descendants().filter(|n| n.tag_name().name() == "host") {
            // Extract comprehensive host data
            let host_obs = self.create_host_observation(&host_node)?;
            observations.push(host_obs);

            // Parse ports for this host
            for port_node in host_node
                .descendants()
                .filter(|n| n.tag_name().name() == "port")
            {
                let port_obs = self.create_service_observation(&host_node, &port_node)?;
                observations.push(port_obs);
            }

            // Parse host scripts
            for script_node in host_node
                .descendants()
                .filter(|n| n.tag_name().name() == "script")
            {
                let script_obs = self.create_script_observation(&host_node, &script_node)?;
                observations.push(script_obs);
            }
        }

        Ok(observations)
    }

    /// Parse masscan XML file (simpler format)
    pub fn parse_masscan_xml(&self, xml_path: &Path) -> Result<Vec<Observation>> {
        let xml_content = std::fs::read_to_string(xml_path)?;
        let doc = Document::parse(&xml_content)?;
        let mut observations = Vec::new();

        // Masscan XML format is different - just hosts and open ports
        for host_node in doc.descendants().filter(|n| n.tag_name().name() == "host") {
            let host_obs = self.create_masscan_host_observation(&host_node)?;
            observations.push(host_obs);

            // Parse masscan ports
            for port_node in host_node
                .descendants()
                .filter(|n| n.tag_name().name() == "port")
            {
                let port_obs = self.create_masscan_service_observation(&host_node, &port_node)?;
                observations.push(port_obs);
            }
        }

        Ok(observations)
    }

    /// Create comprehensive host observation from nmap XML (based on legacy Host.rs)
    fn create_host_observation(&self, host_node: &roxmltree::Node) -> Result<Observation> {
        let mut fields = Map::new();
        let mut primary_ip = String::new();

        // Parse host status
        if let Some(status_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "status")
        {
            if let Some(status) = status_node.attribute("state") {
                fields.insert("status".to_string(), status.into());
            }
        }

        // Parse addresses (IPv4, IPv6, MAC) - based on legacy Host.rs
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

        // Parse hostname - based on legacy Host.rs
        if let Some(hostname_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "hostnames")
            .and_then(|n| n.children().find(|n| n.tag_name().name() == "hostname"))
        {
            if let Some(hostname) = hostname_node.attribute("name") {
                fields.insert("hostname".to_string(), hostname.into());
            }
        }

        // Parse uptime information - based on legacy Host.rs
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

        // Parse distance - based on legacy Host.rs
        if let Some(distance_node) = host_node
            .children()
            .find(|n| n.tag_name().name() == "distance")
        {
            if let Some(distance) = distance_node.attribute("value") {
                fields.insert("distance".to_string(), distance.into());
            }
        }

        // Parse OS information - based on legacy Host.rs
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

        // Parse extraports - based on legacy Host.rs
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
            raw: None,
        })
    }

    /// Create service observation from nmap XML port node (based on legacy Service.rs)
    fn create_service_observation(
        &self,
        host_node: &roxmltree::Node,
        port_node: &roxmltree::Node,
    ) -> Result<Observation> {
        let mut fields = Map::new();

        // Get host IP
        let host_ip = host_node
            .children()
            .find(|n| n.tag_name().name() == "address" && n.attribute("addrtype") == Some("ipv4"))
            .and_then(|n| n.attribute("addr"))
            .unwrap_or("");
        fields.insert("ip".to_string(), host_ip.into());

        // Get port information
        let port = port_node.attribute("portid").unwrap_or("0");
        let protocol = port_node.attribute("protocol").unwrap_or("tcp");
        fields.insert("port".to_string(), port.into());
        fields.insert("protocol".to_string(), protocol.into());

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

        // Get service information - based on legacy Service.rs
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
            if let Some(banner) = service_node.attribute("servicefp") {
                fields.insert("banner".to_string(), banner.into());
            }
            if let Some(conf) = service_node.attribute("conf") {
                fields.insert("confidence".to_string(), conf.into());
            }
        }

        // Get CPE information
        let mut cpe_list = Vec::new();
        for cpe_node in port_node
            .descendants()
            .filter(|n| n.tag_name().name() == "cpe")
        {
            if let Some(cpe_text) = cpe_node.text() {
                cpe_list.push(cpe_text.to_string());
            }
        }
        if !cpe_list.is_empty() {
            fields.insert("cpe".to_string(), cpe_list.join(",").into());
        }

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

    /// Create script observation from nmap XML (based on legacy Script.rs)
    fn create_script_observation(
        &self,
        host_node: &roxmltree::Node,
        script_node: &roxmltree::Node,
    ) -> Result<Observation> {
        let mut fields = Map::new();

        // Get host IP
        let host_ip = host_node
            .children()
            .find(|n| n.tag_name().name() == "address" && n.attribute("addrtype") == Some("ipv4"))
            .and_then(|n| n.attribute("addr"))
            .unwrap_or("");
        fields.insert("ip".to_string(), host_ip.into());

        // Get script information
        let script_id = script_node.attribute("id").unwrap_or("");
        let script_output = script_node.attribute("output").unwrap_or("");
        fields.insert("script_id".to_string(), script_id.into());
        fields.insert("script_output".to_string(), script_output.into());

        // Parse script elements
        let mut elements = HashMap::new();
        for elem_node in script_node
            .children()
            .filter(|n| n.tag_name().name() == "elem")
        {
            if let Some(key) = elem_node.attribute("key") {
                let value = elem_node.text().unwrap_or("");
                elements.insert(key.to_string(), value.to_string());
            }
        }
        if !elements.is_empty() {
            fields.insert(
                "script_elements".to_string(),
                serde_json::to_string(&elements).unwrap().into(),
            );
        }

        // Extract CVE IDs from script output (regex-based)
        let cve_regex = regex::Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap();
        let cve_ids: Vec<String> = cve_regex
            .find_iter(script_output)
            .map(|m| m.as_str().to_string())
            .collect();
        if !cve_ids.is_empty() {
            fields.insert("cve_ids".to_string(), cve_ids.join(",").into());
        }

        let key = format!("script-{}-{}", host_ip, script_id);

        Ok(Observation {
            scan_id: self.scan_id,
            kind: ObservationKind::Banner,
            fields,
            ts: chrono::Utc::now(),
            key,
            raw: Some(script_output.to_string()),
        })
    }

    /// Create session observation from nmap XML (based on legacy Session.rs)
    fn create_session_observation(&self, doc: &Document) -> Result<Observation> {
        let mut fields = Map::new();

        // Get nmaprun node
        let nmaprun_node = doc
            .root()
            .first_child()
            .ok_or_else(|| anyhow::anyhow!("No root element"))?;

        // Parse session information
        if let Some(version) = nmaprun_node.attribute("version") {
            fields.insert("nmap_version".to_string(), version.into());
        }
        if let Some(args) = nmaprun_node.attribute("args") {
            fields.insert("scan_args".to_string(), args.into());
        }
        if let Some(start) = nmaprun_node.attribute("startstr") {
            fields.insert("start_time".to_string(), start.into());
        }

        // Parse finish time from finished node
        if let Some(finished_node) = doc
            .descendants()
            .find(|n| n.tag_name().name() == "finished")
        {
            if let Some(timestr) = finished_node.attribute("timestr") {
                fields.insert("finish_time".to_string(), timestr.into());
            }
        }

        // Parse runstats
        if let Some(hosts_node) = doc.descendants().find(|n| n.tag_name().name() == "hosts") {
            if let Some(total) = hosts_node.attribute("total") {
                fields.insert("total_hosts".to_string(), total.into());
            }
            if let Some(up) = hosts_node.attribute("up") {
                fields.insert("up_hosts".to_string(), up.into());
            }
            if let Some(down) = hosts_node.attribute("down") {
                fields.insert("down_hosts".to_string(), down.into());
            }
        }

        // Parse scan info
        if let Some(scaninfo_node) = doc
            .descendants()
            .find(|n| n.tag_name().name() == "scaninfo")
        {
            if let Some(scan_type) = scaninfo_node.attribute("type") {
                fields.insert("scan_type".to_string(), scan_type.into());
            }
            if let Some(protocol) = scaninfo_node.attribute("protocol") {
                fields.insert("protocol".to_string(), protocol.into());
            }
            if let Some(numservices) = scaninfo_node.attribute("numservices") {
                fields.insert("num_services".to_string(), numservices.into());
            }
        }

        Ok(Observation {
            scan_id: self.scan_id,
            kind: ObservationKind::Metric,
            fields,
            ts: chrono::Utc::now(),
            key: "session".to_string(),
            raw: None,
        })
    }

    /// Create host observation from masscan XML (simplified format)
    fn create_masscan_host_observation(&self, host_node: &roxmltree::Node) -> Result<Observation> {
        let mut fields = Map::new();

        // Masscan XML is simpler - just extract IP
        if let Some(addr) = host_node.attribute("addr") {
            fields.insert("ip".to_string(), addr.into());
            fields.insert("ipv4".to_string(), addr.into());
            fields.insert("status".to_string(), "up".into()); // masscan only reports up hosts
        }

        let host_ip = host_node.attribute("addr").unwrap_or("unknown");
        let key = format!("host-{}", host_ip);

        Ok(Observation {
            scan_id: self.scan_id,
            kind: ObservationKind::Host,
            fields,
            ts: chrono::Utc::now(),
            key,
            raw: None,
        })
    }

    /// Create service observation from masscan XML
    fn create_masscan_service_observation(
        &self,
        host_node: &roxmltree::Node,
        port_node: &roxmltree::Node,
    ) -> Result<Observation> {
        let mut fields = Map::new();

        let host_ip = host_node.attribute("addr").unwrap_or("");
        let port = port_node.attribute("portid").unwrap_or("0");
        let protocol = port_node.attribute("protocol").unwrap_or("tcp");

        fields.insert("ip".to_string(), host_ip.into());
        fields.insert("port".to_string(), port.into());
        fields.insert("protocol".to_string(), protocol.into());
        fields.insert("state".to_string(), "open".into()); // masscan only reports open ports
        fields.insert("reason".to_string(), "syn-ack".into());

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
}
