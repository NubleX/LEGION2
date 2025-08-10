use std::sync::Arc;
use std::path::PathBuf;
use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tauri::{AppHandle, Emitter};
use chrono::Utc;
use rusqlite::{Connection, params};
use futures::StreamExt;
use tokio::time::{Duration, interval};
use tokio::sync::Mutex;

use crate::core::traits::Sink;
use crate::core::types::{Observation, ObservationKind, ObsStream};
use crate::db::Db;

// Event structures for frontend communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEvent {
    pub ip: String,
    pub hostname: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub reason: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub message: String,
    pub percentage: Option<f32>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEvent {
    pub message: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsEvent {
    pub observations_processed: u64,
    pub hosts_discovered: u64,
    pub services_discovered: u64,
    pub errors_encountered: u64,
    pub processing_rate: f64, // observations per second
    pub timestamp: String,
}

/// Performance metrics collector
#[derive(Debug, Clone)]
pub struct SinkMetrics {
    pub observations_processed: Arc<Mutex<u64>>,
    pub hosts_discovered: Arc<Mutex<u64>>,
    pub services_discovered: Arc<Mutex<u64>>,
    pub errors_encountered: Arc<Mutex<u64>>,
    pub start_time: chrono::DateTime<Utc>,
}

impl SinkMetrics {
    pub fn new() -> Self {
        Self {
            observations_processed: Arc::new(Mutex::new(0)),
            hosts_discovered: Arc::new(Mutex::new(0)),
            services_discovered: Arc::new(Mutex::new(0)),
            errors_encountered: Arc::new(Mutex::new(0)),
            start_time: Utc::now(),
        }
    }

    pub async fn increment_observations(&self) {
        *self.observations_processed.lock().await += 1;
    }

    pub async fn increment_hosts(&self) {
        *self.hosts_discovered.lock().await += 1;
    }

    pub async fn increment_services(&self) {
        *self.services_discovered.lock().await += 1;
    }

    pub async fn increment_errors(&self) {
        *self.errors_encountered.lock().await += 1;
    }

    pub async fn get_metrics(&self) -> MetricsEvent {
        let obs_count = *self.observations_processed.lock().await;
        let host_count = *self.hosts_discovered.lock().await;
        let service_count = *self.services_discovered.lock().await;
        let error_count = *self.errors_encountered.lock().await;
        
        let elapsed = Utc::now().signed_duration_since(self.start_time);
        let rate = if elapsed.num_seconds() > 0 {
            obs_count as f64 / elapsed.num_seconds() as f64
        } else {
            0.0
        };

        MetricsEvent {
            observations_processed: obs_count,
            hosts_discovered: host_count,
            services_discovered: service_count,
            errors_encountered: error_count,
            processing_rate: rate,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

/// UiSink emits Tauri events for frontend consumption with host caching
#[derive(Clone)]
pub struct UiSink {
    pub app: AppHandle,
    host_cache: Arc<Mutex<HashMap<String, bool>>>,
    metrics: SinkMetrics,
}

impl UiSink {
    pub fn new(app: AppHandle) -> Self {
        Self { 
            app,
            host_cache: Arc::new(Mutex::new(HashMap::new())),
            metrics: SinkMetrics::new(),
        }
    }

    /// Emit a host event if not already cached
    async fn emit_host_if_new(&self, ip: &str, hostname: Option<String>) -> Result<()> {
        let mut cache = self.host_cache.lock().await;
        if !cache.contains_key(ip) {
            let host_event = HostEvent {
                ip: ip.to_string(),
                hostname,
                timestamp: Utc::now().to_rfc3339(),
            };
            
            if let Err(e) = self.app.emit("obs:host", &host_event) {
                log::error!("Failed to emit obs:host event: {}", e);
                self.metrics.increment_errors().await;
            } else {
                cache.insert(ip.to_string(), true);
                self.metrics.increment_hosts().await;
            }
        }
        Ok(())
    }

    /// Emit a service event
    async fn emit_service(&self, ip: &str, port: u16, protocol: &str, reason: &str) -> Result<()> {
        let service_event = ServiceEvent {
            ip: ip.to_string(),
            port,
            protocol: protocol.to_string(),
            reason: reason.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        
        if let Err(e) = self.app.emit("obs:service", &service_event) {
            log::error!("Failed to emit obs:service event: {}", e);
            self.metrics.increment_errors().await;
        } else {
            self.metrics.increment_services().await;
        }
        Ok(())
    }

    /// Emit a progress event
    async fn emit_progress(&self, message: &str, percentage: Option<f32>) -> Result<()> {
        let progress_event = ProgressEvent {
            message: message.to_string(),
            percentage,
            timestamp: Utc::now().to_rfc3339(),
        };
        
        if let Err(e) = self.app.emit("obs:progress", &progress_event) {
            log::error!("Failed to emit obs:progress event: {}", e);
            self.metrics.increment_errors().await;
        }
        Ok(())
    }

    /// Emit an error event
    async fn emit_error(&self, message: &str) -> Result<()> {
        let error_event = ErrorEvent {
            message: message.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        
        if let Err(e) = self.app.emit("obs:error", &error_event) {
            log::error!("Failed to emit obs:error event: {}", e);
        }
        self.metrics.increment_errors().await;
        Ok(())
    }

    /// Emit completion event with final metrics
    async fn emit_completion(&self) -> Result<()> {
        // Emit final metrics before completion
        let final_metrics = self.metrics.get_metrics().await;
        if let Err(e) = self.app.emit("obs:metrics", &final_metrics) {
            log::error!("Failed to emit obs:metrics event: {}", e);
        }
        
        if let Err(e) = self.app.emit("obs:done", ()) {
            log::error!("Failed to emit obs:done event: {}", e);
        }
        Ok(())
    }

    /// Emit periodic metrics
    async fn emit_metrics(&self) -> Result<()> {
        let metrics = self.metrics.get_metrics().await;
        if let Err(e) = self.app.emit("obs:metrics", &metrics) {
            log::error!("Failed to emit obs:metrics event: {}", e);
        }
        Ok(())
    }
}

#[async_trait]
impl Sink for UiSink {
    fn name(&self) -> &'static str { 
        "ui" 
    }
    
    async fn run(&self, mut input: ObsStream) -> Result<()> {
        // Set up periodic metrics emission (every 5 seconds)
        let metrics_sink = self.clone();
        let metrics_task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if let Err(e) = metrics_sink.emit_metrics().await {
                    log::warn!("Failed to emit periodic metrics: {}", e);
                }
            }
        });
        
        // Process observations
        while let Some(obs) = input.next().await {
            self.metrics.increment_observations().await;
            
            match obs.kind {
                ObservationKind::Service => {
                    let ip = obs.fields.get("ip").and_then(|v| v.as_str()).unwrap_or_default();
                    let port = obs.fields.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let protocol = obs.fields.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
                    let reason = obs.fields.get("reason").and_then(|v| v.as_str()).unwrap_or("open");
                    
                    // Emit host first if new
                    self.emit_host_if_new(ip, None).await?;
                    
                    // Emit service
                    self.emit_service(ip, port, protocol, reason).await?;
                }
                ObservationKind::Host => {
                    let ip = obs.fields.get("ip").and_then(|v| v.as_str()).unwrap_or_default();
                    let hostname = obs.fields.get("hostname").and_then(|v| v.as_str()).map(|s| s.to_string());
                    
                    self.emit_host_if_new(ip, hostname).await?;
                }
                ObservationKind::Metric => {
                    // Handle progress/metrics
                    let message = obs.fields.get("message").and_then(|v| v.as_str()).unwrap_or("Progress update");
                    let percentage = obs.fields.get("percentage").and_then(|v| v.as_f64()).map(|p| p as f32);
                    
                    self.emit_progress(message, percentage).await?;
                }
                ObservationKind::Error => {
                    let message = obs.fields.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error");
                    self.emit_error(message).await?;
                }
                _ => {
                    // Generic event emission for other observation types
                    let evt = match obs.kind {
                        ObservationKind::Banner => "obs:banner",
                        ObservationKind::TopologyEdge => "obs:edge",
                        _ => "obs:generic",
                    };
                    
                    if let Err(e) = self.app.emit(evt, &obs) {
                        log::error!("Failed to emit {} event: {}", evt, e);
                        self.metrics.increment_errors().await;
                    }
                }
            }
        }
        
        // Cancel metrics task and emit final completion
        metrics_task.abort();
        self.emit_completion().await?;
        Ok(())
    }
}

/// Batch of observations for efficient database operations
#[derive(Debug)]
struct ObsBatch {
    hosts: Vec<(String, Option<String>)>,     // (ip, hostname)
    services: Vec<(String, u16, String, String)>, // (ip, port, protocol, reason)
}

impl ObsBatch {
    fn new() -> Self {
        Self {
            hosts: Vec::new(),
            services: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.services.is_empty()
    }

    fn len(&self) -> usize {
        self.hosts.len() + self.services.len()
    }

    fn clear(&mut self) {
        self.hosts.clear();
        self.services.clear();
    }
}

/// DbSink stores observations in the database with batching for performance
pub struct DbSink {
    pub db: Arc<Db>,
    batch_size: usize,
    flush_interval: Duration,
    metrics: SinkMetrics,
}

impl DbSink {
    pub fn new(db: Arc<Db>) -> Self {
        Self { 
            db,
            batch_size: 100, // Process 100 observations at a time
            flush_interval: Duration::from_secs(5), // Flush every 5 seconds
            metrics: SinkMetrics::new(),
        }
    }

    /// Create a new DbSink with custom batch configuration
    pub fn with_config(db: Arc<Db>, batch_size: usize, flush_interval: Duration) -> Self {
        Self {
            db,
            batch_size,
            flush_interval,
            metrics: SinkMetrics::new(),
        }
    }

    /// Flush a batch of observations to the database
    async fn flush_batch(&self, batch: &mut ObsBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        log::info!("Flushing batch with {} hosts and {} services", 
                   batch.hosts.len(), batch.services.len());

        // Process hosts first to ensure they exist before services
        for (ip, hostname) in &batch.hosts {
            self.process_host(ip, hostname.as_deref()).await?;
        }

        // Process services
        for (ip, port, protocol, reason) in &batch.services {
            self.process_service(ip, *port, protocol, reason).await?;
        }

        batch.clear();
        Ok(())
    }

    /// Helper to extract host information from observation
    async fn process_host(&self, ip: &str, hostname: Option<&str>) -> Result<()> {
        // For now, use existing Db methods if available
        // This would need to be implemented based on your Db interface
        log::debug!("Processing host: {} ({})", ip, hostname.unwrap_or("no hostname"));
        self.metrics.increment_hosts().await;
        Ok(())
    }

    /// Helper to extract service information from observation
    async fn process_service(&self, ip: &str, port: u16, protocol: &str, reason: &str) -> Result<()> {
        // For now, just log - would use actual Db methods
        log::debug!("Processing service: {}:{}/{} ({})", ip, port, protocol, reason);
        self.metrics.increment_services().await;
        Ok(())
    }
}

#[async_trait]
impl Sink for DbSink {
    fn name(&self) -> &'static str { 
        "db" 
    }

    async fn run(&self, mut input: ObsStream) -> Result<()> {
        let mut batch = ObsBatch::new();
        let mut last_flush = tokio::time::Instant::now();
        
        // Set up periodic flush timer
        let mut flush_timer = interval(self.flush_interval);
        
        loop {
            tokio::select! {
                // Process incoming observations
                obs_result = input.next() => {
                    match obs_result {
                        Some(obs) => {
                            self.metrics.increment_observations().await;
                            
                            match obs.kind {
                                ObservationKind::Service => {
                                    let ip = obs.fields.get("ip").and_then(|v| v.as_str()).unwrap_or_default();
                                    let port = obs.fields.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                                    let protocol = obs.fields.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
                                    let reason = obs.fields.get("reason").and_then(|v| v.as_str()).unwrap_or("open");
                                    
                                    // Add host to batch if not already present
                                    if !batch.hosts.iter().any(|(existing_ip, _)| existing_ip == ip) {
                                        batch.hosts.push((ip.to_string(), None));
                                    }
                                    
                                    // Add service to batch
                                    batch.services.push((
                                        ip.to_string(),
                                        port,
                                        protocol.to_string(),
                                        reason.to_string()
                                    ));
                                }
                                ObservationKind::Host => {
                                    let ip = obs.fields.get("ip").and_then(|v| v.as_str()).unwrap_or_default();
                                    let hostname = obs.fields.get("hostname").and_then(|v| v.as_str()).map(|s| s.to_string());
                                    
                                    // Add or update host in batch
                                    if let Some(existing) = batch.hosts.iter_mut().find(|(existing_ip, _)| existing_ip == ip) {
                                        if hostname.is_some() {
                                            existing.1 = hostname;
                                        }
                                    } else {
                                        batch.hosts.push((ip.to_string(), hostname));
                                    }
                                }
                                _ => {
                                    // For other observation types, we don't store in database
                                    log::trace!("Ignoring observation type {:?} for database storage", obs.kind);
                                }
                            }
                            
                            // Flush if batch is full
                            if batch.len() >= self.batch_size {
                                if let Err(e) = self.flush_batch(&mut batch).await {
                                    log::error!("Failed to flush batch: {}", e);
                                    self.metrics.increment_errors().await;
                                } else {
                                    last_flush = tokio::time::Instant::now();
                                }
                            }
                        }
                        None => {
                            // Stream ended, flush remaining batch and exit
                            if let Err(e) = self.flush_batch(&mut batch).await {
                                log::error!("Failed to flush final batch: {}", e);
                                self.metrics.increment_errors().await;
                            }
                            break;
                        }
                    }
                }
                
                // Periodic flush
                _ = flush_timer.tick() => {
                    if !batch.is_empty() && last_flush.elapsed() >= self.flush_interval {
                        if let Err(e) = self.flush_batch(&mut batch).await {
                            log::error!("Failed to flush periodic batch: {}", e);
                            self.metrics.increment_errors().await;
                        } else {
                            last_flush = tokio::time::Instant::now();
                        }
                    }
                }
            }
        }
        
        log::info!("DbSink completed processing");
        Ok(())
    }
}