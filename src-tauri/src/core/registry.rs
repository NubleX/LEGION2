//      mk_source: Box<dyn Fn(&str) -> Result<Box<dyn Source>> + Send + Sync>,
//      mk_transform: Box<dyn Fn(&str) -> Result<Box<dyn Transform>> + Send + Sync>, 
//      mk_sink: Box<dyn Fn(&str) -> Result<Box<dyn Sink>> + Send + Sync>,

use anyhow::{Result, anyhow};
use tauri::AppHandle;
use std::sync::Arc;
use std::collections::HashMap;

use super::traits::{Sink, Source};
use crate::plan::Plan;
use super::sinks::{UiSink, DbSink};
use crate::database::Db;
use crate::scanning::masscan::MasscanScanner;
use crate::scanning::nmap::NmapScanner;

/// Registry for managing scanning components and their lifecycle
pub struct Registry {
    db: Arc<Db>,
    app_handle: AppHandle,
    sources: HashMap<String, Box<dyn Source>>,
    sinks: HashMap<String, Box<dyn Sink>>,
}

impl Registry {
    pub fn new(db: Arc<Db>, app_handle: AppHandle) -> Self {
        Self { 
            db,
            app_handle,
            sources: HashMap::new(),
            sinks: HashMap::new(),
        }
    }

    /// Create a source from configuration
    pub async fn create_source(&self, plan: &Plan) -> Result<Box<dyn Source>> {
        match plan.source_type.as_str() {
            "masscan" => {
                let scanner = MasscanScanner::new()?;
                Ok(Box::new(scanner))
            }
            "nmap" => {
                let scanner = NmapScanner::new();
                Ok(Box::new(scanner))
            }
            _ => Err(anyhow!("Unknown source type: {}", plan.source_type))
        }
    }

    /// Create sinks from configuration
    pub fn create_sinks(&self, plan: &Plan) -> Result<Vec<Box<dyn Sink>>> {
        let mut sinks = Vec::new();

        for sink_type in &plan.sink_types {
            match sink_type.as_str() {
                "ui" => sinks.push(Box::new(UiSink::new(self.app_handle.clone())) as Box<dyn Sink>),
                "db" => sinks.push(Box::new(DbSink::new(self.db.clone())) as Box<dyn Sink>),
                _ => log::warn!("Unknown sink type: {}, skipping", sink_type),
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
        self.sources.insert(name, source);
    }

    /// Register a new sink
    pub fn register_sink(&mut self, name: String, sink: Box<dyn Sink>) {
        self.sinks.insert(name, sink);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Add tests here
}