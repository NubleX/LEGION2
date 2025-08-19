// LEGION2 - Transform components for data processing pipeline
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::analysis::types::{Confidence, Finding, Severity, Vulnerability};
use crate::core::traits::Transform;
use crate::database::{CveDatabase, ExploitDb};
use crate::shared::{ObsStream, Observation, ObservationKind, ServiceInfo};
use crate::utils::netsniffer::log_artifact;
use crate::utils::parsing::lookup_vendor;
use crate::utils::parsing::OutputParser;
use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::json;
use std::sync::Arc;

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
                if let Some(banner) = obs.fields.get("banner").and_then(|v| v.as_str()) {
                    // Parse banner for additional version info if not already present
                    if !obs.fields.contains_key("service") {
                        if let Some(service_name) = extract_service_from_banner(banner) {
                            obs.fields
                                .insert("service".to_string(), service_name.into());
                        }
                    }

                    // Extract additional product info
                    if !obs.fields.contains_key("product") {
                        if let Some(product) = extract_product_from_banner(banner) {
                            obs.fields.insert("product".to_string(), product.into());
                        }
                    }
                }

                // Add service classification
                if let Some(port) = obs.fields.get("port").and_then(|v| v.as_u64()) {
                    let service_type = classify_service_by_port(port as u16);
                    obs.fields
                        .insert("service_category".to_string(), service_type.into());
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

/// Classifies network service by port number with security context
fn classify_service_by_port(port: u16) -> ServiceInfo {
    match port {
        // Remote Access
        22 => ServiceInfo::new("SSH", "remote_access", Severity::Medium),
        23 => ServiceInfo::new("Telnet", "remote_access", Severity::High), // Insecure
        3389 => ServiceInfo::new("RDP", "remote_desktop", Severity::High),

        // Email Services
        25 => ServiceInfo::new("SMTP", "email", Severity::Medium),
        110 => ServiceInfo::new("POP3", "email", Severity::Medium),
        143 => ServiceInfo::new("IMAP", "email", Severity::Medium),
        465 => ServiceInfo::new("SMTPS", "email_secure", Severity::Low),
        587 => ServiceInfo::new("SMTP (Submission)", "email", Severity::Medium),
        993 => ServiceInfo::new("IMAPS", "email_secure", Severity::Low),
        995 => ServiceInfo::new("POP3S", "email_secure", Severity::Low),

        // Web Services
        80 => ServiceInfo::new("HTTP", "web", Severity::Medium),
        443 => ServiceInfo::new("HTTPS", "web_secure", Severity::Low),
        8080 | 8000 | 8443 | 8888 => {
            ServiceInfo::new("Web Proxy/Alt HTTP", "web", Severity::Medium)
        }

        // DNS
        53 => ServiceInfo::new("DNS", "dns", Severity::Medium),

        // File Transfer
        21 => ServiceInfo::new("FTP", "file_transfer", Severity::High),
        69 => ServiceInfo::new("TFTP", "file_transfer", Severity::High),

        // Databases
        3306 => ServiceInfo::new("MySQL", "database", Severity::High),
        5432 => ServiceInfo::new("PostgreSQL", "database", Severity::High),
        1433 => ServiceInfo::new("MSSQL", "database", Severity::High),
        1521 => ServiceInfo::new("Oracle DB", "database", Severity::High),
        27017 => ServiceInfo::new("MongoDB", "database", Severity::Medium),

        // Cache / Messaging
        6379 => ServiceInfo::new("Redis", "cache", Severity::Medium),
        11211 => ServiceInfo::new("Memcached", "cache", Severity::Medium),

        // System / Infrastructure
        2222 => ServiceInfo::new("DirectAdmin", "admin_panel", Severity::Medium),
        3344 => ServiceInfo::new("PDProxy", "proxy", Severity::Medium),
        5900 => ServiceInfo::new("VNC", "remote_desktop", Severity::High),
        5000 => ServiceInfo::new("UPnP", "discovery", Severity::Medium),

        // Default range for system ports
        _ if port >= 1 && port <= 1023 => {
            ServiceInfo::new("System Service", "system_service", Severity::Medium)
        }

        // Application-specific or dynamic ports
        _ => ServiceInfo::new("Unknown", "application", Severity::Unknown),
    }
}

pub struct VulnerabilityTransform {
    cve_db: Arc<CveDatabase>,
    exploit_db: Arc<ExploitDb>,
}

impl Transform for VulnerabilityTransform {
    fn name(&self) -> &'static str {
        "vulnerability_enrichment"
    }
    fn apply(&self, mut obs: Observation) -> Option<Observation> {
        if obs.kind != ObservationKind::Service {
            return Some(obs);
        }

        // Check for vulnerabilities
        if let (Some(product), Some(version)) =
            (obs.fields.get("product"), obs.fields.get("version"))
        {
            let cves = self
                .cve_db
                .search_by_product_version(product.as_str()?, version.as_str()?);

            if !cves.is_empty() {
                obs.fields.insert(
                    "vulnerabilities".into(),
                    serde_json::to_value(cves).unwrap(),
                );

                // Check for exploits
                for cve in &cves {
                    if let Some(exploit) = self.exploit_db.search_cve(&cve.id) {
                        obs.fields
                            .insert("exploits".into(), serde_json::to_value(exploit).unwrap());
                    }
                }
            }
        }

        Some(obs)
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

                let vendor = if mac_bytes.len() == 6 {
                    let mac_array: [u8; 6] = mac_bytes.try_into().unwrap();
                    lookup_vendor(&mac_array).unwrap_or("Unknown")
                } else {
                    "Unknown"
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

fn main() {
    let xml_content = std::fs::read_to_string("roxmltree::Node").unwrap();
    create_comprehensive_host_observation(&xml_content);
}

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
