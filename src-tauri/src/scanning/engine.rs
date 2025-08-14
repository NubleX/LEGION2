// Engine contract for LEGION2 scanning system
// Provides a clean observation/source/sink abstraction for scan engines

use std::net::IpAddr;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;

/// Core observation types that scanning engines produce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Observation {
    ServiceFound {
        ip: IpAddr,
        port: u16,
        protocol: String,
        reason: String,
        timestamp: DateTime<Utc>,
    },
    HostFound {
        ip: IpAddr,
        hostname: Option<String>,
        timestamp: DateTime<Utc>,
    },
    Progress {
        message: String,
        percentage: Option<f32>,
        timestamp: DateTime<Utc>,
    },
    Error {
        message: String,
        timestamp: DateTime<Utc>,
    },
}

/// Source trait for producing observations from scanning tools
#[async_trait]
pub trait Source: Send + Sync {
    async fn next_observation(&mut self) -> Result<Option<Observation>>;
    async fn is_finished(&self) -> bool;
}

/// Sink trait for consuming observations (UI, database, etc.)
#[async_trait]
pub trait Sink: Send + Sync {
    async fn consume(&mut self, observation: Observation) -> Result<()>;
    async fn flush(&mut self) -> Result<()>;
}

/// Engine that connects sources to sinks
pub struct Engine {
    sources: Vec<Box<dyn Source>>,
    sinks: Vec<Box<dyn Sink>>,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            sinks: Vec::new(),
        }
    }

    pub fn add_source(&mut self, source: Box<dyn Source>) {
        self.sources.push(source);
    }

    pub fn add_sink(&mut self, sink: Box<dyn Sink>) {
        self.sinks.push(sink);
    }

    /// Run the engine - consume from all sources and feed to all sinks
    pub async fn run(&mut self) -> Result<()> {
        loop {
            let mut any_active = false;

            // Process each source
            for source in &mut self.sources {
                if !source.is_finished().await {
                    any_active = true;
                    
                    // Get next observation
                    if let Some(observation) = source.next_observation().await? {
                        // Send to all sinks
                        for sink in &mut self.sinks {
                            if let Err(e) = sink.consume(observation.clone()).await {
                                log::error!("Sink failed to consume observation: {}", e);
                            }
                        }
                    }
                }
            }

            // If no sources are active, we're done
            if !any_active {
                break;
            }

            // Small delay to prevent tight loop
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // Flush all sinks
        for sink in &mut self.sinks {
            if let Err(e) = sink.flush().await {
                log::error!("Failed to flush sink: {}", e);
            }
        }

        Ok(())
    }
}