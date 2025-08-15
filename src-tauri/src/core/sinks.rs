use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

use crate::analysis::AnalysisEngine;
use crate::core::traits::Sink;
use crate::database::Db;
use crate::shared::{ObsStream, ObservationKind};

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
                    let ip = obs
                        .fields
                        .get("ip")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let port = obs.fields.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let protocol = obs
                        .fields
                        .get("protocol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tcp");
                    let reason = obs
                        .fields
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("open");

                    // Emit host first if new
                    self.emit_host_if_new(ip, None).await?;

                    // Emit service
                    self.emit_service(ip, port, protocol, reason).await?;
                }
                ObservationKind::Host => {
                    let ip = obs
                        .fields
                        .get("ip")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let hostname = obs
                        .fields
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    self.emit_host_if_new(ip, hostname).await?;
                }
                ObservationKind::Metric => {
                    // Handle progress/metrics
                    let message = obs
                        .fields
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Progress update");
                    let percentage = obs
                        .fields
                        .get("percentage")
                        .and_then(|v| v.as_f64())
                        .map(|p| p as f32);

                    self.emit_progress(message, percentage).await?;
                }
                ObservationKind::Error => {
                    let message = obs
                        .fields
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
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
    hosts: Vec<(String, Option<String>)>,         // (ip, hostname)
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

/// Database Sink - persists observations to SQLite
#[derive(Debug)]
pub struct DbSink {
    db: Arc<Db>,
    metrics: SinkMetrics,
}

impl DbSink {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            metrics: SinkMetrics::new(),
        }
    }

    async fn store_host(&self, ip: &str, hostname: Option<&str>) -> Result<()> {
        self.db.upsert_host(ip, hostname).await?;
        self.metrics.increment_hosts().await;
        Ok(())
    }

    async fn store_service(&self, ip: &str, port: u16, protocol: &str, state: &str) -> Result<()> {
        self.db
            .upsert_service(ip, port, protocol, Some(state))
            .await?;
        self.metrics.increment_services().await;
        Ok(())
    }
}

#[async_trait]
impl Sink for DbSink {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn run(&self, mut stream: ObsStream) -> Result<()> {
        while let Some(observation) = stream.next().await {
            match observation.kind {
                ObservationKind::Host => {
                    if let Some(ip) = observation.fields.get("ip").and_then(|v| v.as_str()) {
                        let hostname = observation.fields.get("hostname").and_then(|v| v.as_str());
                        if let Err(e) = self.store_host(ip, hostname).await {
                            eprintln!("Failed to store host {}: {}", ip, e);
                            self.metrics.increment_errors().await;
                        }
                    }
                }
                ObservationKind::Service => {
                    if let (Some(ip), Some(port), Some(protocol)) = (
                        observation.fields.get("ip").and_then(|v| v.as_str()),
                        observation
                            .fields
                            .get("port")
                            .and_then(|v| v.as_u64())
                            .map(|p| p as u16),
                        observation.fields.get("protocol").and_then(|v| v.as_str()),
                    ) {
                        let state = observation
                            .fields
                            .get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("open");
                        if let Err(e) = self.store_service(ip, port, protocol, state).await {
                            eprintln!(
                                "Failed to store service {}:{}/{}: {}",
                                ip, port, protocol, e
                            );
                            self.metrics.increment_errors().await;
                        }
                    }
                }
                ObservationKind::Error => {
                    if let Some(message) =
                        observation.fields.get("message").and_then(|v| v.as_str())
                    {
                        eprintln!("Database sink encountered scan error: {}", message);
                        self.metrics.increment_errors().await;
                    }
                }
                _ => {
                    // Other observation types (Banner, TopologyEdge, Metric) don't need DB storage for now
                }
            }

            self.metrics.increment_observations().await;
        }

        Ok(())
    }
}
