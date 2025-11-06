// LEGION2 - Transform components for data processing pipeline
// Copyright (c) 2025 NubleX / Igor Dunaev
// use crate::analysis::types::{Confidence, Finding, Severity, Vulnerability}; // Temporarily disabled - needs refactoring
use crate::shared::traits::Transform;
// CveDatabase and ExploitDb removed - using main Db instead
use crate::scanners::netsniffer::log_artifact;
// use crate::utils::parsing::lookup_vendor; // Function doesn't exist yet
use crate::shared::shared::{
    classify_service_by_port, ObsStream, Observation, ObservationKind, ServiceInfo,
};
use crate::utils::parsing::OutputParser;
use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::json;

/// Transform that enriches observations with parsed IP addresses
pub struct IpEnrichmentTransform;

impl IpEnrichmentTransform {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transform for IpEnrichmentTransform {
    fn name(&self) -> &'static str {
        "ip_enrichment"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        let enriched_stream = input.map(|mut obs| {
            if let Some(ref raw_line) = obs.raw {
                // Extract IPs from raw output and create host observations
                let ips = OutputParser::extract_ip_addresses(raw_line);
                if !ips.is_empty() {
                    log::debug!("Extracted IPs from line: {:?}", ips);
                    // Could add the IPs to the observation fields
                    obs.fields.insert(
                        "extracted_ips".to_string(),
                        serde_json::Value::Array(
                            ips.into_iter().map(serde_json::Value::String).collect(),
                        ),
                    );
                }
            }
            obs
        });

        Ok(enriched_stream.boxed())
    }
}

/// Transform that parses service information from raw output
pub struct ServiceParsingTransform;

impl ServiceParsingTransform {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transform for ServiceParsingTransform {
    fn name(&self) -> &'static str {
        "service_parsing"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        let enriched_stream = input.map(|mut obs| {
            if obs.kind == ObservationKind::Service {
                // Enhance service observations with additional parsing
                if let Some(banner) = obs.fields.get("banner").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                    // Parse banner for additional version info if not already present
                    if !obs.fields.contains_key("service") {
                        if let Some(service_name) = extract_service_from_banner(&banner) {
                            obs.fields
                                .insert("service".to_string(), service_name.into());
                        }
                    }

                    // Extract additional product info
                    if !obs.fields.contains_key("product") {
                        if let Some(product) = extract_product_from_banner(&banner) {
                            obs.fields.insert("product".to_string(), product.into());
                        }
                    }
                }

                // Add service classification
                if let Some(port) = obs.fields.get("port").and_then(|v| v.as_u64()) {
                    let service_type = classify_service_by_port(port as u16);
                    obs.fields
                        .insert("service_category".to_string(), service_type.category.into());
                }
            }
            obs
        });

        Ok(enriched_stream.boxed())
    }
}

/// Extract service name from banner
fn extract_service_from_banner(banner: &str) -> Option<String> {
    let banner_lower = banner.to_lowercase();
    if banner_lower.contains("ssh") {
        Some("ssh".to_string())
    } else if banner_lower.contains("http") {
        Some("http".to_string())
    } else if banner_lower.contains("ftp") {
        Some("ftp".to_string())
    } else if banner_lower.contains("smtp") {
        Some("smtp".to_string())
    } else if banner_lower.contains("mysql") {
        Some("mysql".to_string())
    } else if banner_lower.contains("postgres") {
        Some("postgresql".to_string())
    } else {
        None
    }
}

/// Extract product name from banner
fn extract_product_from_banner(banner: &str) -> Option<String> {
    let banner_lower = banner.to_lowercase();
    if banner_lower.contains("openssh") {
        Some("OpenSSH".to_string())
    } else if banner_lower.contains("apache") {
        Some("Apache".to_string())
    } else if banner_lower.contains("nginx") {
        Some("nginx".to_string())
    } else if banner_lower.contains("microsoft") {
        Some("Microsoft".to_string())
    } else {
        None
    }
}

pub struct VulnerabilityTransform {
    // TODO: Implement vulnerability database integration
    // Currently disabled pending proper database structure
}

impl VulnerabilityTransform {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Transform for VulnerabilityTransform {
    fn name(&self) -> &'static str {
        "vulnerability_enrichment"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        // TODO: Implement vulnerability checking
        // For now, just pass through observations unchanged
        Ok(input)
    }
}

/// Transform that tracks progress information
pub struct ProgressTrackingTransform;

impl ProgressTrackingTransform {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transform for ProgressTrackingTransform {
    fn name(&self) -> &'static str {
        "progress_tracking"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        let progress_stream = input.map(|mut obs| {
            if let Some(ref raw_line) = obs.raw {
                // Extract progress information
                if let Some(progress) = OutputParser::parse_nmap_progress(raw_line) {
                    log::debug!("Scan progress: {}%", progress);
                    obs.fields.insert(
                        "progress_percent".to_string(),
                        serde_json::Value::Number((progress as i32).into()),
                    );
                    obs.fields.insert(
                        "progress_message".to_string(),
                        serde_json::Value::String(format!("Scan {}% complete", progress)),
                    );
                }
            }
            obs
        });

        Ok(progress_stream.boxed())
    }
}

/// Transform that enriches host observations with MAC vendor information
/// Uses OUI (Organizationally Unique Identifier) lookups from netsniffer data
pub struct MacEnrichmentTransform {
    // OUI map for MAC vendor lookups - could be loaded from file or embedded
    oui_map: std::sync::Arc<std::collections::HashMap<[u8; 3], String>>,
}

impl MacEnrichmentTransform {
    pub fn new() -> Self {
        // Initialize OUI map with common vendors
        let mut oui_map = std::collections::HashMap::new();

        // Add common OUI prefixes (these would typically be loaded from a database)
        // Format: [first 3 bytes of MAC] -> Vendor Name
        oui_map.insert([0x00, 0x50, 0x56], "VMware".to_string());
        oui_map.insert([0x00, 0x0C, 0x29], "VMware".to_string());
        oui_map.insert([0x00, 0x1C, 0x42], "Parallels".to_string());
        oui_map.insert([0x08, 0x00, 0x27], "Oracle VirtualBox".to_string());
        oui_map.insert([0x00, 0x15, 0x5D], "Microsoft Hyper-V".to_string());
        oui_map.insert([0xD8, 0x9E, 0xF3], "Google".to_string());
        oui_map.insert([0x00, 0x1A, 0x11], "Google".to_string());
        oui_map.insert([0xF0, 0x18, 0x98], "Apple".to_string());
        oui_map.insert([0x00, 0x50, 0xF2], "Microsoft".to_string());
        oui_map.insert([0x00, 0x23, 0x12], "Cisco Systems".to_string());
        oui_map.insert([0x00, 0x1B, 0x44], "Cisco-Linksys".to_string());
        oui_map.insert([0x00, 0x04, 0x20], "Cisco Systems".to_string());
        oui_map.insert([0xB8, 0x27, 0xEB], "Raspberry Pi Foundation".to_string());
        oui_map.insert([0xDC, 0xA6, 0x32], "Raspberry Pi Trading".to_string());
        oui_map.insert([0x00, 0x1C, 0xC0], "TP-Link".to_string());
        oui_map.insert([0x74, 0xDA, 0x38], "D-Link".to_string());
        oui_map.insert([0x00, 0x11, 0x32], "Synology".to_string());
        oui_map.insert([0x00, 0x90, 0x4C], "NETGEAR".to_string());

        Self {
            oui_map: std::sync::Arc::new(oui_map),
        }
    }

    /// Lookup vendor by MAC address
    fn lookup_vendor(&self, mac: &str) -> Option<String> {
        // Parse MAC address (format: AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
        let parts: Vec<&str> = mac.split(|c| c == ':' || c == '-').collect();
        if parts.len() < 3 {
            return None;
        }

        let oui: [u8; 3] = [
            u8::from_str_radix(parts[0], 16).ok()?,
            u8::from_str_radix(parts[1], 16).ok()?,
            u8::from_str_radix(parts[2], 16).ok()?,
        ];

        self.oui_map.get(&oui).cloned()
    }
}

#[async_trait]
impl Transform for MacEnrichmentTransform {
    fn name(&self) -> &'static str {
        "mac_enrichment"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        let oui_map = self.oui_map.clone();

        let enriched_stream = input.map(move |mut obs| {
            if obs.kind == ObservationKind::Host {
                // Check if we have MAC address and need vendor lookup
                // Extract all needed values first to avoid borrow conflicts
                let (mac_str, vendor_needed) = {
                    let mac_str = obs.fields.get("mac_address").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let has_vendor = obs.fields.contains_key("vendor");
                    let vendor_value = obs.fields.get("vendor").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let vendor_needed = !has_vendor || vendor_value.as_deref() == Some("Unknown");
                    (mac_str, vendor_needed)
                };
                
                if let Some(mac) = mac_str {
                    if vendor_needed {
                        // Parse MAC OUI and lookup vendor
                        let parts: Vec<&str> = mac.split(|c| c == ':' || c == '-').collect();
                        if parts.len() >= 3 {
                            if let (Ok(b1), Ok(b2), Ok(b3)) = (
                                u8::from_str_radix(parts[0], 16),
                                u8::from_str_radix(parts[1], 16),
                                u8::from_str_radix(parts[2], 16),
                            ) {
                                let oui = [b1, b2, b3];
                                if let Some(vendor) = oui_map.get(&oui) {
                                    let vendor_clone = vendor.clone();
                                    let oui_str = format!("{:02X}:{:02X}:{:02X}", b1, b2, b3);
                                    obs.fields.insert("vendor".to_string(), vendor_clone.clone().into());
                                    obs.fields.insert("oui".to_string(), oui_str.into());
                                    log::debug!("Enriched MAC {} with vendor: {}", mac, vendor_clone);
                                }
                            }
                        }
                    }
                }
            }
            obs
        });

        Ok(enriched_stream.boxed())
    }
}

/// Transform that performs passive OS detection using network fingerprints
/// Combines TTL analysis, TCP window size, and TCP options from netsniffer
pub struct PassiveOsTransform;

impl PassiveOsTransform {
    pub fn new() -> Self {
        Self
    }

    /// Detect OS family from TTL value
    fn detect_os_from_ttl(ttl: u8) -> Option<String> {
        match ttl {
            253..=255 => Some("Linux/Unix (TTL 255)".to_string()),
            125..=128 => Some("Windows (TTL 128)".to_string()),
            61..=64 => Some("Linux/Unix (TTL 64)".to_string()),
            29..=32 => Some("Unix/AIX (TTL 32)".to_string()),
            _ => None,
        }
    }

    /// Detect OS from TCP window size and other TCP parameters
    fn detect_os_from_tcp_signature(window: u16, ttl: u8, mss: Option<u16>, wscale: Option<u8>) -> Option<String> {
        // Common TCP signatures for OS detection
        match (window, ttl, mss) {
            // Windows signatures
            (8192, 128, Some(1460)) => Some("Windows 7/8/10".to_string()),
            (65535, 128, Some(1460)) => Some("Windows XP/2003".to_string()),
            (16384, 128, _) => Some("Windows Server".to_string()),

            // Linux signatures
            (5840, 64, Some(1460)) => Some("Linux 2.6.x".to_string()),
            (29200, 64, Some(1460)) => Some("Linux 3.x/4.x".to_string()),
            (14600, 64, _) if wscale.is_some() => Some("Modern Linux".to_string()),

            // macOS/BSD signatures
            (65535, 64, Some(1460)) => Some("macOS/BSD".to_string()),
            (32768, 64, Some(1460)) => Some("macOS 10.x".to_string()),

            // IoT/Embedded signatures
            (5840, 64, Some(536)) => Some("Embedded Linux".to_string()),
            (_, 255, _) => Some("Network Device/Router".to_string()),

            _ => None,
        }
    }
}

#[async_trait]
impl Transform for PassiveOsTransform {
    fn name(&self) -> &'static str {
        "passive_os"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        let enriched_stream = input.map(|mut obs| {
            if obs.kind == ObservationKind::Host {
                // Passive OS detection from TTL
                if let Some(ttl) = obs.fields.get("ttl").and_then(|v| v.as_u64()) {
                    if let Some(os_guess) = Self::detect_os_from_ttl(ttl as u8) {
                        if !obs.fields.contains_key("os_name") {
                            obs.fields.insert("passive_os".to_string(), os_guess.into());
                            obs.fields.insert("os_detection_method".to_string(), "passive_ttl".into());
                        }
                    }
                }

                // Enhanced OS detection from TCP signature
                if let (Some(ttl), Some(tcp_win)) = (
                    obs.fields.get("ttl").and_then(|v| v.as_u64()),
                    obs.fields.get("tcp_window").and_then(|v| v.as_u64()),
                ) {
                    let mss = obs.fields.get("tcp_mss").and_then(|v| v.as_u64()).map(|v| v as u16);
                    let wscale = obs.fields.get("tcp_wscale").and_then(|v| v.as_u64()).map(|v| v as u8);

                    if let Some(os_guess) = Self::detect_os_from_tcp_signature(
                        tcp_win as u16,
                        ttl as u8,
                        mss,
                        wscale,
                    ) {
                        let os_guess_clone = os_guess.clone();
                        obs.fields.insert("passive_os".to_string(), os_guess.into());
                        obs.fields.insert("os_detection_method".to_string(), "passive_tcp_signature".into());
                        log::debug!("Passive OS detection: {} (TTL={}, Window={})", os_guess_clone, ttl, tcp_win);
                    }
                }

                // Add confidence score based on available data
                let mut confidence_score = 0;
                if obs.fields.contains_key("ttl") { confidence_score += 20; }
                if obs.fields.contains_key("tcp_window") { confidence_score += 30; }
                if obs.fields.contains_key("tcp_mss") { confidence_score += 20; }
                if obs.fields.contains_key("tcp_wscale") { confidence_score += 15; }
                if obs.fields.contains_key("tcp_sack_ok") { confidence_score += 15; }

                if confidence_score > 0 {
                    obs.fields.insert("passive_os_confidence".to_string(), confidence_score.into());
                }
            }
            obs
        });

        Ok(enriched_stream.boxed())
    }
}

/// Composite transform that applies multiple transforms in sequence
pub struct CompositeTransform {
    transforms: Vec<Box<dyn Transform>>,
}

impl CompositeTransform {
    pub fn new() -> Self {
        Self {
            transforms: vec![
                Box::new(IpEnrichmentTransform::new()),
                Box::new(ServiceParsingTransform::new()),
                Box::new(ProgressTrackingTransform::new()),
            ],
        }
    }

    /// Create a composite transform from module names using the module registry
    pub fn from_modules(module_names: &[String]) -> anyhow::Result<Self> {
        let registry = crate::modules::get_registry();
        let transforms = registry.build_transform_pipeline(module_names)?;

        Ok(Self { transforms })
    }

    pub fn with_transform(mut self, transform: Box<dyn Transform>) -> Self {
        self.transforms.push(transform);
        self
    }
}
//  Parse Nmap XML to Enrich MACs

pub fn parse_host_xml(xml_content: &str) {
    let mut reader = Reader::from_str(xml_content);
    let mut buf = Vec::new();

    let mut ip = String::new();
    let mut mac = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"address" => {
                let mut kind = String::new();
                let mut addr = String::new();

                for attr in e.attributes() {
                    let attr = attr.unwrap();
                    match attr.key.as_ref() {
                        b"addrtype" => kind = String::from_utf8(attr.value.to_vec()).unwrap(),
                        b"addr" => addr = String::from_utf8(attr.value.to_vec()).unwrap(),
                        _ => (),
                    }
                }

                if kind == "mac" {
                    mac = addr.clone();
                } else if kind == "ipv4" {
                    ip = addr.clone();
                }
            }

            Ok(Event::End(ref e)) if e.name().as_ref() == b"host" => {
                // Log enriched artifact
                let mac_bytes: Vec<u8> = mac
                    .split(':')
                    .map(|s| u8::from_str_radix(s, 16).unwrap_or(0))
                    .collect();

                let vendor = "Unknown"; // TODO: Implement lookup_vendor function

                let artifact = json!({
                    "ts": chrono::Utc::now().to_rfc3339(),
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "source": "nmap"
                });

                log_artifact(artifact);
                mac.clear();
                ip.clear();
            }

            Ok(Event::Eof) => break,
            Err(e) => panic!("Error parsing XML: {}", e),
            _ => (),
        }
        buf.clear();
    }
}

// fn main() {
//     let xml_content = std::fs::read_to_string("roxmltree::Node").unwrap();
//     create_comprehensive_host_observation(&xml_content);
// }

#[async_trait]
impl Transform for CompositeTransform {
    fn name(&self) -> &'static str {
        "composite"
    }

    async fn apply(&self, mut input: ObsStream) -> Result<ObsStream> {
        // Apply transforms sequentially
        for transform in &self.transforms {
            log::debug!("Applying transform: {}", transform.name());
            input = transform.apply(input).await?;
        }
        Ok(input)
    }
}
