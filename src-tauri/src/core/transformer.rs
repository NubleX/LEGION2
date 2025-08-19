// LEGION2 - Transform components for data processing pipeline
// Copyright (c) 2025 NubleX / Igor Dunaev
// use crate::analysis::types::{Confidence, Finding, Severity, Vulnerability}; // Temporarily disabled - needs refactoring
use crate::shared::traits::Transform;
// CveDatabase and ExploitDb removed - using main Db instead
use crate::network::netsniffer::log_artifact;
// use crate::utils::parsing::lookup_vendor; // Function doesn't exist yet
use crate::shared::shared::{classify_service_by_port, ServiceInfo, ObsStream, Observation, ObservationKind};
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

pub struct VulnerabilityTransform {
    // TODO: Implement vulnerability database integration
    // Currently disabled pending proper database structure
}

impl VulnerabilityTransform {
    pub fn new() -> Self {
        Self {}
    }
}

impl Transform for VulnerabilityTransform {
    fn name(&self) -> &'static str {
        "vulnerability_enrichment"
    }

    fn apply(&self, obs: Observation) -> Option<Observation> {
        // TODO: Implement vulnerability checking
        // For now, just pass through observations unchanged
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
