// LEGION2 - Transform components for data processing pipeline
// Copyright (c) 2025 NubleX / Igor Dunaev

use async_trait::async_trait;
use anyhow::Result;
use futures::{stream, StreamExt};
use crate::core::traits::Transform;
use crate::shared::{Observation, ObsStream};
use crate::utils::parsing::OutputParser;

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
                    obs.fields.insert("extracted_ips".to_string(), 
                                         serde_json::Value::Array(ips.into_iter()
                                                                 .map(serde_json::Value::String)
                                                                 .collect()));
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
        let parsed_stream = input.map(|mut obs| {
            if let Some(ref raw_line) = obs.raw {
                // Extract service info from raw output
                if let Some((service, version)) = OutputParser::extract_service_info(raw_line) {
                    log::debug!("Extracted service: {} (version: {:?})", service, version);
                    obs.fields.insert("detected_service".to_string(), 
                                         serde_json::Value::String(service));
                    if let Some(ver) = version {
                        obs.fields.insert("service_version".to_string(), 
                                             serde_json::Value::String(ver));
                    }
                }
                
                // Extract ports
                let ports = OutputParser::extract_ports(raw_line);
                if !ports.is_empty() {
                    log::debug!("Extracted ports from line: {:?}", ports);
                    obs.fields.insert("detected_ports".to_string(), 
                                         serde_json::Value::Array(ports.into_iter()
                                                                 .map(|p| serde_json::Value::Number((p as i32).into()))
                                                                 .collect()));
                }
            }
            obs
        });

        Ok(parsed_stream.boxed())
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
                    obs.fields.insert("progress_percent".to_string(), 
                                             serde_json::Value::Number((progress as i32).into()));
                    obs.fields.insert("progress_message".to_string(), 
                                             serde_json::Value::String(format!("Scan {}% complete", progress)));
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