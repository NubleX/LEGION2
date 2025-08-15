//      mk_source: Box<dyn Fn(&str) -> Result<Box<dyn Source>> + Send + Sync>,
//      mk_transform: Box<dyn Fn(&str) -> Result<Box<dyn Transform>> + Send + Sync>,
//      mk_sink: Box<dyn Fn(&str) -> Result<Box<dyn Sink>> + Send + Sync>,

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::AppHandle;

use super::sinks::{DbSink, UiSink, VulnerabilityAnalysisSink};
use super::traits::{Sink, Source, Transform};
use super::transforms::{IpEnrichmentTransform, ServiceParsingTransform, ProgressTrackingTransform};
use crate::analysis::AnalysisEngine;
use crate::database::Db;
use crate::plan::Plan;
use crate::scanning::masscan::MasscanScanner;
use crate::scanning::nmap::NmapScanner;

/// Registry for managing scanning components and their lifecycle

pub struct Registry {
    db: Arc<Db>,
    app_handle: AppHandle,
    analysis_engine: Arc<AnalysisEngine>,
    sources: HashMap<String, Box<dyn Source>>,
    sinks: HashMap<String, Box<dyn Sink>>,
    transforms: HashMap<String, Box<dyn Transform>>,
}

impl Registry {
    pub fn new(db: Arc<Db>, app_handle: AppHandle) -> Self {
        // Create analysis engine internally - keep registry simple
        let analysis_engine = Arc::new(AnalysisEngine::new(db.clone()));

        let mut registry = Self {
            db: db.clone(),
            app_handle: app_handle.clone(),
            analysis_engine,
            sources: HashMap::new(),
            sinks: HashMap::new(),
            transforms: HashMap::new(),
        };

        // Register standard sinks on startup
        registry.register_sink("ui".to_string(), Box::new(UiSink::new(app_handle)));
        registry.register_sink("db".to_string(), Box::new(DbSink::new(db)));

        registry
    }

    /// Create a source from configuration using registry or dynamic creation
    pub async fn create_source(&self, plan: &Plan) -> Result<Box<dyn Source>> {
        // First try to get from registry
        if let Some(_registered_source) = self.get_source(&plan.source_type) {
            // For now, create new instances since we can't clone trait objects easily
            // In the future, we could use Arc<dyn Source> for shared instances
            match plan.source_type.as_str() {
                "masscan" => {
                    let scanner = MasscanScanner::new()?;
                    Ok(Box::new(scanner))
                }
                "nmap" => {
                    let scanner = NmapScanner::new();
                    Ok(Box::new(scanner))
                }
                _ => Err(anyhow!(
                    "Registered source type {} cannot be cloned",
                    plan.source_type
                )),
            }
        } else {
            // Fallback to dynamic creation for runtime registration
            match plan.source_type.as_str() {
                "masscan" => {
                    let scanner = MasscanScanner::new()?;
                    Ok(Box::new(scanner))
                }
                "nmap" => {
                    let scanner = NmapScanner::new();
                    Ok(Box::new(scanner))
                }
                _ => Err(anyhow!("Unknown source type: {}", plan.source_type)),
            }
        }
    }

    /// Create sinks from configuration using registered components
    pub fn create_sinks(&self, plan: &Plan) -> Result<Vec<Box<dyn Sink>>> {
        let mut sinks = Vec::new();

        for sink_type in &plan.sink_types {
            // First try to get from registry
            if let Some(_registered_sink) = self.get_sink(sink_type) {
                // For now, create new instances since we can't clone trait objects easily
                // In the future, we could use Arc<dyn Sink> for shared instances
                match sink_type.as_str() {
                    "ui" => {
                        sinks.push(Box::new(UiSink::new(self.app_handle.clone())) as Box<dyn Sink>)
                    }
                    "db" => sinks.push(Box::new(DbSink::new(self.db.clone())) as Box<dyn Sink>),
                    "vulnerability" => sinks.push(Box::new(VulnerabilityAnalysisSink::new(self.db.clone(), self.app_handle.clone())) as Box<dyn Sink>),
                    _ => log::warn!(
                        "Registered sink type {} cannot be cloned, creating new instance",
                        sink_type
                    ),
                }
            } else {
                // Fallback to dynamic creation for unknown types
                log::warn!("Sink type {} not registered, skipping", sink_type);
            }
        }

        if sinks.is_empty() {
            return Err(anyhow!("No valid sinks created from plan"));
        }

        Ok(sinks)
    }

    /// Get a registered source
    pub fn get_source(&self, name: &str) -> Option<&Box<dyn Source>> {
        self.sources.get(name)
    }

    /// Get a registered sink
    pub fn get_sink(&self, name: &str) -> Option<&Box<dyn Sink>> {
        self.sinks.get(name)
    }

    /// Register a new source
    pub fn register_source(&mut self, name: String, source: Box<dyn Source>) {
        log::info!("Registering source: {}", name);
        self.sources.insert(name, source);
    }

    /// Register a new sink
    pub fn register_sink(&mut self, name: String, sink: Box<dyn Sink>) {
        log::info!("Registering sink: {}", name);
        self.sinks.insert(name, sink);
    }

    /// Get a registered transform
    pub fn get_transform(&self, name: &str) -> Option<&Box<dyn Transform>> {
        self.transforms.get(name)
    }

    /// Register a new transform
    pub fn register_transform(&mut self, name: String, transform: Box<dyn Transform>) {
        log::info!("Registering transform: {}", name);
        self.transforms.insert(name, transform);
    }

    /// Initialize all standard sources and sinks
    pub async fn initialize_standard_components(&mut self) -> Result<()> {
        log::info!("Initializing standard registry components");

        // Register standard sources (creating dummy instances for registry tracking)
        // Note: We create lightweight instances just for registration purposes
        match MasscanScanner::new() {
            Ok(scanner) => {
                self.register_source("masscan".to_string(), Box::new(scanner));
            }
            Err(e) => log::warn!("Failed to register masscan source: {}", e),
        }

        let nmap_scanner = NmapScanner::new();
        self.register_source("nmap".to_string(), Box::new(nmap_scanner));
        
        // Register standard transforms
        self.register_transform("ip_enrichment".to_string(), Box::new(IpEnrichmentTransform::new()));
        self.register_transform("service_parsing".to_string(), Box::new(ServiceParsingTransform::new()));
        self.register_transform("progress_tracking".to_string(), Box::new(ProgressTrackingTransform::new()));

        // Register standard sinks (lightweight instances for registry)
        self.register_sink("ui".to_string(), Box::new(UiSink::new(self.app_handle.clone())));
        self.register_sink("db".to_string(), Box::new(DbSink::new(self.db.clone())));
        self.register_sink("vulnerability".to_string(), Box::new(VulnerabilityAnalysisSink::new(self.db.clone(), self.app_handle.clone())));

        log::info!(
            "Registry initialized with {} sources, {} sinks, and {} transforms",
            self.sources.len(),
            self.sinks.len(),
            self.transforms.len()
        );
        Ok(())
    }

    /// List all registered component types
    pub fn list_components(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let sources: Vec<String> = self.sources.keys().cloned().collect();
        let sinks: Vec<String> = self.sinks.keys().cloned().collect();
        let transforms: Vec<String> = self.transforms.keys().cloned().collect();
        (sources, sinks, transforms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Add tests here
}
