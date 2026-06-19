// LEGION2 - Transform components for data processing pipeline
// Copyright (c) 2025 NubleX / Igor Dunaev
// use crate::analysis::types::{Confidence, Finding, Severity, Vulnerability}; // Temporarily disabled - needs refactoring
use crate::shared::traits::Transform;
// CveDatabase and ExploitDb removed - using main Db instead
use crate::scanners::netsniffer::log_artifact;
// use crate::utils::parsing::lookup_vendor; // Function doesn't exist yet
use crate::shared::shared::{
    classify_service_by_port, ObsStream, Observation, ObservationKind,
};
use crate::utils::parsing::OutputParser;
use anyhow::Result;
use async_trait::async_trait;
use futures::{StreamExt, stream};
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
                        // Try to use netsniffer OUI lookup first (more comprehensive)
                        let mac_bytes_vec: Vec<u8> = mac.split(|c| c == ':' || c == '-')
                            .take(6)
                            .filter_map(|s| u8::from_str_radix(s, 16).ok())
                            .collect();
                        
                        if mac_bytes_vec.len() >= 6 {
                            let oui = [mac_bytes_vec[0], mac_bytes_vec[1], mac_bytes_vec[2]];
                            
                            // Use netsniffer OUI lookup function (more comprehensive database)
                            // Note: oui_lookup_vendor takes [u8; 6] but only uses first 3 bytes
                            let mac_array = [
                                mac_bytes_vec[0],
                                mac_bytes_vec[1],
                                mac_bytes_vec[2],
                                mac_bytes_vec.get(3).copied().unwrap_or(0),
                                mac_bytes_vec.get(4).copied().unwrap_or(0),
                                mac_bytes_vec.get(5).copied().unwrap_or(0),
                            ];
                            
                            if let Some(vendor) = crate::scanners::netsniffer::oui_lookup_vendor(mac_array) {
                                let vendor_clone = vendor.clone();
                                let oui_str = format!("{:02X}:{:02X}:{:02X}", oui[0], oui[1], oui[2]);
                                obs.fields.insert("vendor".to_string(), vendor_clone.clone().into());
                                obs.fields.insert("nic_vendor".to_string(), vendor_clone.clone().into());
                                obs.fields.insert("oui".to_string(), oui_str.into());
                                
                                // Mark for database persistence
                                obs.fields.insert("persist_mac_vendor".to_string(), true.into());
                                
                                log::debug!("Enriched MAC {} with vendor (netsniffer): {}", mac, vendor_clone);
                            } else {
                                // Fallback to local OUI map - use the OUI we already parsed
                                if let Some(vendor) = oui_map.get(&oui) {
                                    let vendor_clone = vendor.clone();
                                    let oui_str = format!("{:02X}:{:02X}:{:02X}", oui[0], oui[1], oui[2]);
                                    obs.fields.insert("vendor".to_string(), vendor_clone.clone().into());
                                    obs.fields.insert("nic_vendor".to_string(), vendor_clone.clone().into());
                                    obs.fields.insert("oui".to_string(), oui_str.into());
                                    
                                    // Mark for database persistence
                                    obs.fields.insert("persist_mac_vendor".to_string(), true.into());
                                    
                                    log::debug!("Enriched MAC {} with vendor (local): {}", mac, vendor_clone);
                                } else {
                                    // Last resort: try lookup_vendor method for any edge cases
                                    let temp_transform = MacEnrichmentTransform {
                                        oui_map: oui_map.clone(),
                                    };
                                    if let Some(vendor) = temp_transform.lookup_vendor(&mac) {
                                        let vendor_clone = vendor.clone();
                                        let oui_str = format!("{:02X}:{:02X}:{:02X}", oui[0], oui[1], oui[2]);
                                        obs.fields.insert("vendor".to_string(), vendor_clone.clone().into());
                                        obs.fields.insert("nic_vendor".to_string(), vendor_clone.clone().into());
                                        obs.fields.insert("oui".to_string(), oui_str.into());
                                        obs.fields.insert("persist_mac_vendor".to_string(), true.into());
                                        log::debug!("Enriched MAC {} with vendor (lookup_vendor): {}", mac, vendor_clone);
                                    }
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
                
                // Store OS detection results in standardized fields for database persistence
                let os_name_opt = obs.fields.get("passive_os").and_then(|v| v.as_str()).map(|s| s.to_string());
                if let Some(os_name) = os_name_opt {
                    // Parse OS name to extract family and type
                    let os_family = if os_name.contains("Linux") {
                        "Linux".to_string()
                    } else if os_name.contains("Windows") {
                        "Windows".to_string()
                    } else if os_name.contains("macOS") || os_name.contains("BSD") {
                        "Unix".to_string()
                    } else {
                        "Unknown".to_string()
                    };
                    
                    obs.fields.insert("os_name".to_string(), os_name.clone().into());
                    obs.fields.insert("os_family".to_string(), os_family.clone().into());
                    
                    // Convert confidence score to accuracy (0-100)
                    let os_accuracy = (confidence_score as f32 / 100.0 * 100.0).min(100.0);
                    obs.fields.insert("os_accuracy".to_string(), os_accuracy.into());
                    
                    // Mark for database persistence
                    obs.fields.insert("persist_os_info".to_string(), true.into());
                    
                    log::debug!("Passive OS detection: {} (family: {}, confidence: {})", os_name, os_family, confidence_score);
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
/// Parses Nmap XML output to extract and enrich MAC addresses with vendor information
/// This function is called from netsniffer commands to process XML scan results
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

                // Use netsniffer OUI lookup if we have a valid MAC
                let vendor = if mac_bytes.len() >= 6 {
                    let mac_array = [
                        mac_bytes[0],
                        mac_bytes[1],
                        mac_bytes[2],
                        mac_bytes.get(3).copied().unwrap_or(0),
                        mac_bytes.get(4).copied().unwrap_or(0),
                        mac_bytes.get(5).copied().unwrap_or(0),
                    ];
                    crate::scanners::netsniffer::oui_lookup_vendor(mac_array)
                        .unwrap_or_else(|| "Unknown".to_string())
                } else {
                    "Unknown".to_string()
                };

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

/// Transform that enriches Service observations with CVE and ExploitDB data
/// Queries CVE database for product/version matches and ExploitDB for associated exploits
pub struct CveExploitEnrichmentTransform {
    cve_db: Option<std::sync::Arc<crate::offensive::cve_db::CveDb>>,
}

impl CveExploitEnrichmentTransform {
    pub fn new() -> Self {
        // Lazy initialization of CVE database - will be created when needed
        Self {
            cve_db: None,
        }
    }

    /// Initialize CVE database connection
    fn init_cve_db(&mut self) -> Result<()> {
        if self.cve_db.is_none() {
            let db = crate::offensive::cve_db::CveDb::new()?;
            self.cve_db = Some(std::sync::Arc::new(db));
            log::debug!("Initialized CVE database connection");
        }
        Ok(())
    }

}

#[async_trait]
impl Transform for CveExploitEnrichmentTransform {
    fn name(&self) -> &'static str {
        "cve_enrichment"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        // Create a mutable clone for database initialization
        let mut self_clone = CveExploitEnrichmentTransform {
            cve_db: self.cve_db.clone(),
        };
        
        // Initialize CVE database if needed
        if let Err(e) = self_clone.init_cve_db() {
            log::warn!("Failed to initialize CVE database, CVE enrichment will be limited: {}", e);
        }

        let cve_db = self_clone.cve_db.clone();
        
        let enriched_stream = input.then(move |obs| {
            let cve_db_clone = cve_db.clone();
            let obs_scan_id = obs.scan_id;
            
            async move {
                let mut observations = vec![obs.clone()];
                
                // Process Service observations to find CVEs
                if obs.kind == ObservationKind::Service {
                    // Extract service information
                    let product = obs.fields.get("product")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let version = obs.fields.get("version")
                        .and_then(|v| v.as_str());
                    let _service_name = obs.fields.get("service")
                        .and_then(|v| v.as_str());
                    let ip = obs.fields.get("ip")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let port = obs.fields.get("port")
                        .and_then(|v| v.as_u64())
                        .map(|p| p as u16);

                    // Only search if we have product information
                    if !product.is_empty() {
                        if let Some(db) = &cve_db_clone {
                            // Search for CVEs
                            let cves = if let Ok(cve_list) = db.search_by_product(product).await {
                                cve_list.into_iter()
                                    .filter(|cve| {
                                        if let Some(ver) = version {
                                            cve.matches_product_version(product, ver)
                                        } else {
                                            true
                                        }
                                    })
                                    .collect()
                            } else {
                                Vec::new()
                            };

                            // Create vulnerability observations for each CVE
                            for cve in cves {
                                // Try to enrich with exploit data
                                let mut enriched_cve = cve.clone();
                                
                                // Search ExploitDB for this CVE
                                if let Ok(mut exploit_db) = crate::offensive::ExploitDb::PyExploitDb::new() {
                                    exploit_db.debug = false;
                                    
                                    if let Ok(()) = exploit_db.open_file().await {
                                        if let Some(exploit) = exploit_db.search_cve(&enriched_cve.name) {
                                            enriched_cve.exploit_id = exploit.id.clone();
                                            enriched_cve.exploit = exploit.description.clone();
                                            enriched_cve.exploit_url = format!("https://www.exploit-db.com/exploits/{}", exploit.id);
                                        }
                                    }
                                }
                                
                                // Store CVE in database
                                if let Err(e) = db.add_cve(&enriched_cve).await {
                                    log::warn!("Failed to store CVE {} in database: {}", enriched_cve.name, e);
                                }
                                
                                // Create vulnerability observation
                                let mut vuln_fields = serde_json::Map::new();
                                vuln_fields.insert("ip".to_string(), ip.into());
                                if let Some(p) = port {
                                    vuln_fields.insert("port".to_string(), p.into());
                                }
                                vuln_fields.insert("cve_id".to_string(), enriched_cve.name.clone().into());
                                vuln_fields.insert("severity".to_string(), format!("{:?}", enriched_cve.severity).to_lowercase().into());
                                vuln_fields.insert("product".to_string(), enriched_cve.product.clone().into());
                                vuln_fields.insert("version".to_string(), enriched_cve.version.clone().into());
                                vuln_fields.insert("url".to_string(), enriched_cve.url.clone().into());
                                vuln_fields.insert("description".to_string(), enriched_cve.description.clone().into());
                                
                                if let Some(score) = enriched_cve.cvss_score {
                                    vuln_fields.insert("cvss_score".to_string(), score.into());
                                }
                                
                                if !enriched_cve.exploit_id.is_empty() && enriched_cve.exploit_id != "unknown" {
                                    vuln_fields.insert("exploit_id".to_string(), enriched_cve.exploit_id.clone().into());
                                    vuln_fields.insert("exploit_url".to_string(), enriched_cve.exploit_url.clone().into());
                                    vuln_fields.insert("exploit_description".to_string(), enriched_cve.exploit.clone().into());
                                }

                                let vuln_obs = Observation {
                                    scan_id: obs_scan_id,
                                    kind: ObservationKind::Error, // Using Error kind for vulnerabilities
                                    fields: vuln_fields,
                                    ts: chrono::Utc::now(),
                                    key: format!("vuln-{}-{}-{}", ip, port.map(|p| p.to_string()).unwrap_or_default(), enriched_cve.name),
                                    raw: None,
                                };
                                
                                observations.push(vuln_obs);
                                log::debug!("Enriched service {}/{} with CVE {}", product, version.unwrap_or("unknown"), enriched_cve.name);
                            }
                        }
                    }
                }
                
                stream::iter(observations)
            }
        })
        .flatten();

        Ok(Box::pin(enriched_stream))
    }
}

/// Transform that correlates port/service combinations with known CVEs
/// Builds port-service-CVE relationships from database lookups
#[derive(Clone)]
pub struct PortServiceCveTransform {
    cve_db: Option<std::sync::Arc<crate::offensive::cve_db::CveDb>>,
}

impl PortServiceCveTransform {
    pub fn new() -> Self {
        Self {
            cve_db: None,
        }
    }

    fn init_cve_db(&mut self) -> Result<()> {
        if self.cve_db.is_none() {
            let db = crate::offensive::cve_db::CveDb::new()?;
            self.cve_db = Some(std::sync::Arc::new(db));
            log::debug!("Initialized CVE database for port-service-CVE correlation");
        }
        Ok(())
    }

    /// Get common CVEs for a specific port/service combination
    async fn get_cves_for_port_service(
        &self,
        port: u16,
        service_name: &str,
        product: Option<&str>,
    ) -> Vec<crate::offensive::CVE::CVE> {
        let mut cves = Vec::new();
        
        if let Some(db) = &self.cve_db {
            // Search by service name first
            if let Ok(service_cves) = db.search_by_product(service_name).await {
                // Filter CVEs that are commonly associated with this port
                // Port-specific filtering can help narrow down relevant CVEs
                for cve in service_cves {
                    // Port can be used to filter CVEs that are specific to certain services
                    // For example, port 22 (SSH) CVEs vs port 80 (HTTP) CVEs
                    if !cves.iter().any(|c: &crate::offensive::CVE::CVE| c.name == cve.name) {
                        cves.push(cve);
                    }
                }
            }
            
            // Also search by product if provided
            if let Some(prod) = product {
                if let Ok(product_cves) = db.search_by_product(prod).await {
                    // Merge with existing CVEs, avoiding duplicates
                    for cve in product_cves {
                        if !cves.iter().any(|c| c.name == cve.name) {
                            cves.push(cve);
                        }
                    }
                }
            }
            
            // Log port-specific CVE search for debugging
            if !cves.is_empty() {
                log::debug!("Found {} CVEs for port {} service {}", cves.len(), port, service_name);
            }
        }
        
        cves
    }
}

#[async_trait]
impl Transform for PortServiceCveTransform {
    fn name(&self) -> &'static str {
        "port_service_cve"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        // Create a mutable clone for database initialization
        let mut self_clone = PortServiceCveTransform {
            cve_db: self.cve_db.clone(),
        };
        
        // Initialize CVE database if needed
        if let Err(e) = self_clone.init_cve_db() {
            log::warn!("Failed to initialize CVE database, port-service-CVE correlation will be limited: {}", e);
        }

        let transform_arc = std::sync::Arc::new(PortServiceCveTransform {
            cve_db: self_clone.cve_db.clone(),
        });
        
        let enriched_stream = input.then(move |obs| {
            let transform = transform_arc.clone();
            async move {
                let mut observations = vec![obs.clone()];
                
                if obs.kind == ObservationKind::Service {
                    // Extract port and service information
                    let port = obs.fields.get("port")
                        .and_then(|v| v.as_u64())
                        .map(|p| p as u16);
                    let service_name = obs.fields.get("service")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let product = obs.fields.get("product")
                        .and_then(|v| v.as_str());

                    if let Some(p) = port {
                        if !service_name.is_empty() {
                            // Add port-service correlation field
                            let mut enriched_obs = obs.clone();
                            enriched_obs.fields.insert(
                                "port_service_key".to_string(),
                                format!("{}-{}", p, service_name).into(),
                            );
                            
                            // Use get_cves_for_port_service to enrich with CVE data
                            let cves = transform.get_cves_for_port_service(p, &service_name, product).await;
                            
                            if !cves.is_empty() {
                                enriched_obs.fields.insert(
                                    "cve_count".to_string(),
                                    cves.len().into(),
                                );
                                enriched_obs.fields.insert(
                                    "cve_ids".to_string(),
                                    serde_json::Value::Array(
                                        cves.iter().map(|c| c.name.clone().into()).collect()
                                    ),
                                );
                                log::debug!("Enriched port {} service {} with {} CVEs", p, service_name, cves.len());
                            }
                            
                            // Mark for CVE correlation (will be processed by CveExploitEnrichmentTransform)
                            enriched_obs.fields.insert(
                                "needs_cve_check".to_string(),
                                true.into(),
                            );
                            
                            observations[0] = enriched_obs;
                        }
                    } else if !service_name.is_empty() {
                        // Even without port, mark service for CVE check
                        let mut enriched_obs = obs.clone();
                        enriched_obs.fields.insert(
                            "needs_cve_check".to_string(),
                            true.into(),
                        );
                            observations[0] = enriched_obs;
                    }
                }
                
                stream::iter(observations)
            }
        })
        .flatten();

        Ok(Box::pin(enriched_stream))
    }
}

/// Transform that performs stealthy hostname discovery by querying known devices
/// Uses protocols like NetBIOS, LLMNR, SMB, mDNS, and local DNS to avoid direct DNS queries
pub struct StealthyHostnameTransform {
    resolver: Option<std::sync::Arc<crate::core::hostname_resolver::HostnameResolver>>,
}

impl StealthyHostnameTransform {
    pub fn new() -> Self {
        Self {
            resolver: None,
        }
    }

    /// Initialize hostname resolver with database connection
    fn init_resolver(&mut self) -> Result<()> {
        if self.resolver.is_none() {
            // Get database path using same logic as main.rs
            let db_dir = Self::app_data_dir();
            std::fs::create_dir_all(&db_dir)?;
            let db_path = db_dir.join("network.db");
            let db = std::sync::Arc::new(crate::database::Db::open(db_path)?);
            
            let resolver = crate::core::hostname_resolver::HostnameResolver::new(db);
            self.resolver = Some(std::sync::Arc::new(resolver));
            log::debug!("Initialized hostname resolver");
        }
        Ok(())
    }

    /// Get app data directory (same logic as main.rs)
    fn app_data_dir() -> std::path::PathBuf {
        std::env::current_exe()
            .unwrap_or_else(|_| std::env::current_dir().unwrap().join("legion2"))
            .parent()
            .unwrap()
            .join(".legion2_data")
    }
}

#[async_trait]
impl Transform for StealthyHostnameTransform {
    fn name(&self) -> &'static str {
        "stealthy_hostname"
    }

    async fn apply(&self, input: ObsStream) -> Result<ObsStream> {
        // Create a mutable clone for resolver initialization
        let mut self_clone = StealthyHostnameTransform {
            resolver: self.resolver.clone(),
        };
        
        // Initialize resolver if needed
        if let Err(e) = self_clone.init_resolver() {
            log::warn!("Failed to initialize hostname resolver, hostname discovery will be skipped: {}", e);
            // Return stream unchanged if resolver initialization fails
            return Ok(input);
        }

        let resolver = self_clone.resolver.clone().unwrap();
        
        // Refresh known hosts from database
        if let Err(e) = resolver.refresh_known_hosts().await {
            log::warn!("Failed to refresh known hosts: {}", e);
        }

        let enriched_stream = input.then(move |obs| {
            let resolver_clone = resolver.clone();
            async move {
                // Only process Host observations that don't have hostnames
                if obs.kind == ObservationKind::Host {
                    let ip_str = obs.fields.get("ip")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    
                    let has_hostname = obs.fields.get("hostname")
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);

                    // Only try to resolve if we have an IP and no hostname
                    if let Some(ip) = ip_str {
                        if !has_hostname {
                            if let Ok(target_ip) = ip.parse::<std::net::IpAddr>() {
                                // Try to resolve hostname using stealthy methods
                                if let Some(hostname) = resolver_clone.resolve_hostname(target_ip).await {
                                    log::info!("Resolved hostname {} for {}", hostname, ip);
                                    let mut enriched_obs = obs.clone();
                                    enriched_obs.fields.insert(
                                        "hostname".to_string(),
                                        hostname.into(),
                                    );
                                    return enriched_obs;
                                }
                            }
                        }
                    }
                }
                
                obs
            }
        });

        Ok(enriched_stream.boxed())
    }
}
