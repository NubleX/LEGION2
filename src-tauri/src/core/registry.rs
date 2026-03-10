//      mk_source: Box<dyn Fn(&str) -> Result<Box<dyn Source>> + Send + Sync>,
//      mk_transform: Box<dyn Fn(&str) -> Result<Box<dyn Transform>> + Send + Sync>,
//      mk_sink: Box<dyn Fn(&str) -> Result<Box<dyn Sink>> + Send + Sync>,

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::AppHandle;

use super::sinks::{DbSink, UiSink, VulnerabilityAnalysisSink};
use crate::shared::traits::{Sink, Source};
use crate::analysis::AnalysisEngine;
use crate::database::Db;
use crate::plan::Plan;
use crate::scanners::masscan::MasscanScanner;
use crate::scanners::nmap::NmapScanner;
use crate::scanners::netsniffer::NetSnifferSource;
use crate::scanners::iot_probe_source::IoTProbeSource;
use crate::scanners::probes::iot_probes::IoTProtocol;
use std::path::PathBuf;

/// Registry for managing scanning components and their lifecycle

#[derive(Clone)]
pub struct Registry {
    db: Arc<Db>,
    app_handle: AppHandle,
    analysis_engine: Arc<AnalysisEngine>,
    // Use shared storage for sources, sinks, and transforms
    sources: Arc<std::sync::Mutex<HashMap<String, String>>>, // Just track names
    sinks: Arc<std::sync::Mutex<HashMap<String, String>>>,
    transforms: Arc<std::sync::Mutex<HashMap<String, String>>>,
}

impl Registry {
    pub fn new(db: Arc<Db>, app_handle: AppHandle) -> Self {
        // Create analysis engine internally - keep registry simple
        let analysis_engine = Arc::new(AnalysisEngine::new(db.clone()));

        let registry = Self {
            db: db.clone(),
            app_handle: app_handle.clone(),
            analysis_engine,
            sources: Arc::new(std::sync::Mutex::new(HashMap::new())),
            sinks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            transforms: Arc::new(std::sync::Mutex::new(HashMap::new())),
        };

        registry
    }

    /// Create a source from configuration using registry or dynamic creation
    pub async fn create_source(&self, plan: &Plan) -> Result<Box<dyn Source>> {
        // Validate source is registered before creating
        if !self.has_source(&plan.source_type) {
            log::warn!("Source type '{}' not registered, attempting to create anyway", plan.source_type);
        }
        
        // Dynamic creation based on plan type
        match plan.source_type.as_str() {
            "masscan" => {
                let scanner = MasscanScanner::new()?;
                Ok(Box::new(scanner))
            }
            "nmap" => {
                let scanner = NmapScanner::new();
                Ok(Box::new(scanner))
            }
            "netsniffer" => {
                // Get interface from plan or use default
                let interface = plan.interface.clone().unwrap_or_else(|| "default".to_string());
                let output_dir = PathBuf::from(".scans");
                let scanner = NetSnifferSource::new(interface, output_dir);
                Ok(Box::new(scanner))
            }
            "iot_probe" => {
                // Parse protocols from plan.extra (stored there by iot_spider)
                let protocols: Vec<IoTProtocol> = plan.extra
                    .iter()
                    .filter_map(|p| IoTProtocol::from_str(p))
                    .collect();
                
                // Default to all protocols if none specified
                let protocols = if protocols.is_empty() {
                    vec![
                        IoTProtocol::SSDP,
                        IoTProtocol::MDNS,
                        IoTProtocol::WSDD,
                        IoTProtocol::SNMP,
                        IoTProtocol::CoAP,
                        IoTProtocol::MQTT,
                    ]
                } else {
                    protocols
                };
                
                // Get interface from plan or use default
                let interface = plan.interface.clone().unwrap_or_else(|| "default".to_string());
                let output_dir = PathBuf::from(".scans");
                let scanner = IoTProbeSource::new(protocols, interface, output_dir);
                Ok(Box::new(scanner))
            }
            _ => Err(anyhow!("Unknown source type: {}", plan.source_type)),
        }
    }

    /// Create sinks from configuration using registered components
    pub fn create_sinks(&self, plan: &Plan) -> Result<Vec<Box<dyn Sink>>> {
        let mut sinks = Vec::new();
        let analysis_engine = self.get_analysis_engine();

        for sink_type in &plan.sink_types {
            // Validate sink is registered before creating
            if !self.has_sink(sink_type) {
                log::warn!("Sink type '{}' not registered, attempting to create anyway", sink_type);
            }
            
            match sink_type.as_str() {
                "ui" => {
                    let mut ui_sink = UiSink::new(self.app_handle.clone());
                    ui_sink.set_analysis_engine(analysis_engine.clone());
                    let discovery_manager = self.get_discovery_manager();
                    ui_sink.set_discovery_manager(discovery_manager.clone());
                    sinks.push(Box::new(ui_sink) as Box<dyn Sink>);
                }
                "db" => {
                    let mut db_sink = DbSink::new(self.db.clone());
                    db_sink.set_analysis_engine(analysis_engine.clone());
                    let discovery_manager = self.get_discovery_manager();
                    db_sink.set_discovery_manager(discovery_manager.clone());
                    sinks.push(Box::new(db_sink) as Box<dyn Sink>);
                }
                "vulnerability" => sinks.push(Box::new(VulnerabilityAnalysisSink::new(
                    self.db.clone(),
                    self.app_handle.clone(),
                )) as Box<dyn Sink>),
                _ => log::warn!("Unknown sink type: {}", sink_type),
            }
        }

        if sinks.is_empty() {
            return Err(anyhow!("No valid sinks created from plan"));
        }

        Ok(sinks)
    }

    /// Check if a source is registered
    /// Useful for validation and dynamic component discovery
    pub fn has_source(&self, name: &str) -> bool {
        self.sources.lock().unwrap().contains_key(name)
    }

    /// Check if a sink is registered
    /// Useful for validation and dynamic component discovery
    pub fn has_sink(&self, name: &str) -> bool {
        self.sinks.lock().unwrap().contains_key(name)
    }
    
    /// Get the analysis engine for triggering analysis operations
    pub fn get_analysis_engine(&self) -> Arc<AnalysisEngine> {
        self.analysis_engine.clone()
    }
    
    /// Get or create the discovery manager for recursive discovery
    pub fn get_discovery_manager(&self) -> Arc<crate::core::discovery_manager::DiscoveryManager> {
        // Lazy initialization - create if not exists
        // Since we can't mutate self, we'll need to use Arc<Mutex> or initialize at creation
        // For now, create a new one each time (will be optimized later)
        let mut manager = crate::core::discovery_manager::DiscoveryManager::new(
            Arc::new(self.clone()),
            self.db.clone(),
        );
        manager = manager.with_app_handle(self.app_handle.clone());
        Arc::new(manager)
    }

    /// Register a new source type
    pub fn register_source(&self, name: String) {
        log::info!("Registering source: {}", name);
        self.sources.lock().unwrap().insert(name.clone(), name);
    }

    /// Register a new sink type
    pub fn register_sink(&self, name: String) {
        log::info!("Registering sink: {}", name);
        self.sinks.lock().unwrap().insert(name.clone(), name);
    }

    /// Register a new transform type
    pub fn register_transform(&self, name: String) {
        log::info!("Registering transform: {}", name);
        self.transforms.lock().unwrap().insert(name.clone(), name);
    }

    /// Initialize all standard sources and sinks
    pub async fn initialize_standard_components(&self) -> Result<()> {
        log::info!("Initializing standard registry components");

        // Register standard sources
        self.register_source("masscan".to_string());
        self.register_source("nmap".to_string());
        self.register_source("netsniffer".to_string());
        self.register_source("iot_probe".to_string());

        // Register standard transforms
        self.register_transform("ip_enrichment".to_string());
        self.register_transform("service_parsing".to_string());
        self.register_transform("progress_tracking".to_string());

        // Register new enhanced transforms
        self.register_transform("xml_parsing".to_string());
        self.register_transform("mac_enrichment".to_string());
        self.register_transform("network_fingerprinting".to_string());
        self.register_transform("vulnerability_analysis".to_string());

        // Register standard sinks
        self.register_sink("ui".to_string());
        self.register_sink("db".to_string());
        self.register_sink("vulnerability".to_string());

        let sources_count = self.sources.lock().unwrap().len();
        let sinks_count = self.sinks.lock().unwrap().len();
        let transforms_count = self.transforms.lock().unwrap().len();

        log::info!(
            "Registry initialized with {} sources, {} sinks, and {} transforms",
            sources_count,
            sinks_count,
            transforms_count
        );
        Ok(())
    }

    /// List all registered component types
    pub fn list_components(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let sources: Vec<String> = self.sources.lock().unwrap().keys().cloned().collect();
        let sinks: Vec<String> = self.sinks.lock().unwrap().keys().cloned().collect();
        let transforms: Vec<String> = self.transforms.lock().unwrap().keys().cloned().collect();
        (sources, sinks, transforms)
    }

    /// Clear active sources and reset registry state
    pub async fn clear_active_sources(&self) {
        log::info!("Clearing active sources in registry");
        // For now, we don't maintain active source state, but this method
        // exists for future state management and cleanup
        // TODO: If we add source lifecycle tracking, clear it here
    }
}

#[cfg(test)]
mod tests {
    // Add tests here
}
