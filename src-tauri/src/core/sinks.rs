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

use crate::core::traits::Sink;
use crate::database::Db;
use crate::shared::{ObsStream, ObservationKind};
use crate::analysis::vulnerability::VulnerabilityEngine;

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

            log::info!("Emitting obs:host event for: {}", host_event.ip);
            if let Err(e) = self.app.emit("obs:host", &host_event) {
                log::error!("Failed to emit obs:host event: {}", e);
                self.metrics.increment_errors().await;
            } else {
                log::debug!("Successfully emitted obs:host event for {}", host_event.ip);
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

        log::info!("Emitting obs:service event for: {}:{}/{}", service_event.ip, service_event.port, service_event.protocol);
        if let Err(e) = self.app.emit("obs:service", &service_event) {
            log::error!("Failed to emit obs:service event: {}", e);
            self.metrics.increment_errors().await;
        } else {
            log::debug!("Successfully emitted obs:service event for {}:{}", service_event.ip, service_event.port);
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

        log::info!("Emitting obs:progress event: {}", progress_event.message);
        if let Err(e) = self.app.emit("obs:progress", &progress_event) {
            log::error!("Failed to emit obs:progress event: {}", e);
            self.metrics.increment_errors().await;
        } else {
            log::debug!("Successfully emitted obs:progress event");
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
                    let _reason = obs
                        .fields
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .or_else(|| obs.fields.get("state").and_then(|v| v.as_str()))
                        .unwrap_or("open");
                    
                    // Get service name and version for enhanced display
                    let service = obs.fields.get("service").and_then(|v| v.as_str()).unwrap_or("");
                    let version = obs.fields.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    
                    // Create detailed service description
                    let service_desc = if !service.is_empty() && !version.is_empty() {
                        format!("{} {}", service, version)
                    } else if !service.is_empty() {
                        service.to_string()
                    } else {
                        "unknown".to_string()
                    };

                    // Emit host first if new
                    self.emit_host_if_new(ip, None).await?;

                    // Emit service with enhanced info
                    self.emit_service(ip, port, protocol, &service_desc).await?;
                    
                    // Also emit as progress to show in live output
                    let progress_msg = format!("Found service: {}:{}/{} - {}", ip, port, protocol, service_desc);
                    self.emit_progress(&progress_msg, None).await?;
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
                    let status = obs
                        .fields
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("up");

                    self.emit_host_if_new(ip, hostname.clone()).await?;
                    
                    // Also emit as progress to show in live output
                    let progress_msg = if let Some(ref hn) = hostname {
                        format!("Host discovered: {} ({}) - {}", ip, hn, status)
                    } else {
                        format!("Host discovered: {} - {}", ip, status)
                    };
                    self.emit_progress(&progress_msg, None).await?;
                }
                ObservationKind::Metric => {
                    // Handle progress/metrics - check for nmap_output first, then message
                    let message = obs
                        .fields
                        .get("nmap_output")
                        .and_then(|v| v.as_str())
                        .or_else(|| obs.fields.get("message").and_then(|v| v.as_str()))
                        .or_else(|| obs.raw.as_deref())
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
}

/// Vulnerability Analysis Sink - analyzes services and emits vulnerability events
pub struct VulnerabilityAnalysisSink {
    vulnerability_engine: VulnerabilityEngine,
    app: AppHandle,
    metrics: SinkMetrics,
    db: Arc<Db>,
}

impl VulnerabilityAnalysisSink {
    pub fn new(db: Arc<Db>, app: AppHandle) -> Self {
        Self {
            vulnerability_engine: VulnerabilityEngine::new(db.clone()),
            app,
            metrics: SinkMetrics::new(),
            db,
        }
    }
    
    async fn emit_vulnerability(&self, vulnerability: &crate::analysis::types::Vulnerability) -> Result<()> {
        #[derive(Serialize)]
        struct VulnerabilityEvent {
            id: String,
            host_ip: String,
            port: u16,
            service: String,
            name: String,
            severity: String,
            description: String,
            cvss_score: Option<f32>,
            timestamp: String,
        }
        
        let vuln_event = VulnerabilityEvent {
            id: vulnerability.finding.id.clone(),
            host_ip: vulnerability.finding.host.clone(),
            port: vulnerability.finding.port.unwrap_or(0),
            service: vulnerability.finding.service.clone().unwrap_or_else(|| "unknown".to_string()),
            name: vulnerability.finding.title.clone(),
            severity: format!("{:?}", vulnerability.finding.severity),
            description: vulnerability.finding.description.clone(),
            cvss_score: vulnerability.cvss_score,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        
        if let Err(e) = self.app.emit("obs:vulnerability", &vuln_event) {
            log::error!("Failed to emit vulnerability event: {}", e);
        } else {
            // Update database vulnerability count
            if let Err(e) = self.db.increment_host_vulnerability_count(&vulnerability.finding.host).await {
                log::error!("Failed to increment vulnerability count for host {}: {}", vulnerability.finding.host, e);
            }
            
            // Also emit as progress message for live output
            let progress_msg = format!(
                "🔍 Vulnerability found: {} on {}:{} - {} ({})",
                vulnerability.finding.title,
                vulnerability.finding.host,
                vulnerability.finding.port.unwrap_or(0),
                vulnerability.finding.service.as_deref().unwrap_or("unknown"),
                format!("{:?}", vulnerability.finding.severity)
            );
            
            if let Err(e) = self.app.emit("obs:progress", &ProgressEvent {
                message: progress_msg,
                percentage: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            }) {
                log::error!("Failed to emit vulnerability progress event: {}", e);
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl Sink for VulnerabilityAnalysisSink {
    fn name(&self) -> &'static str {
        "vulnerability_analysis"
    }
    
    async fn run(&self, mut input: ObsStream) -> anyhow::Result<()> {
        while let Some(obs) = input.next().await {
            self.metrics.increment_observations().await;
            
            match obs.kind {
                ObservationKind::Service => {
                    // Extract service information
                    if let (Some(ip), Some(port), Some(service)) = (
                        obs.fields.get("ip").and_then(|v| v.as_str()),
                        obs.fields.get("port").and_then(|v| v.as_u64()).map(|p| p as u16),
                        obs.fields.get("service").and_then(|v| v.as_str()),
                    ) {
                        // Run vulnerability analysis on this service
                        match self.vulnerability_engine.analyze_service(ip, port, service).await {
                            Ok(vulnerabilities) => {
                                for vuln in vulnerabilities {
                                    if let Err(e) = self.emit_vulnerability(&vuln).await {
                                        log::error!("Failed to emit vulnerability: {}", e);
                                        self.metrics.increment_errors().await;
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Vulnerability analysis failed for {}:{} ({}): {}", ip, port, service, e);
                                self.metrics.increment_errors().await;
                            }
                        }
                    }
                }
                _ => {
                    // Don't process other observation types for vulnerability analysis
                }
            }
        }
        Ok(())
    }
}

impl DbSink {
    async fn store_host(&self, ip: &str, hostname: Option<&str>, status: Option<&str>) -> Result<()> {
        self.db.upsert_host(ip, hostname, status).await?;
        self.metrics.increment_hosts().await;
        Ok(())
    }

    async fn store_host_network_info(&self, ip: &str, mac_address: Option<&str>, vendor: Option<&str>) -> Result<()> {
        self.db.update_host_network_info(ip, mac_address, vendor).await?;
        Ok(())
    }

    async fn store_service(&self, ip: &str, port: u16, protocol: &str, state: &str) -> Result<()> {
        self.db
            .upsert_service(ip, port, protocol, Some(state))
            .await?;
        self.metrics.increment_services().await;
        Ok(())
    }

    async fn store_service_detailed(&self, ip: &str, port: u16, protocol: &str, state: &str, service: Option<&str>, version: Option<&str>, banner: Option<&str>) -> Result<()> {
        self.db
            .upsert_service_detailed(ip, port, protocol, Some(state), service, version, banner)
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
                        let status = observation.fields.get("status").and_then(|v| v.as_str());
                        let mac_address = observation.fields.get("mac_address").and_then(|v| v.as_str());
                        let vendor = observation.fields.get("vendor").and_then(|v| v.as_str());
                        
                        if let Err(e) = self.store_host(ip, hostname, status).await {
                            eprintln!("Failed to store host {}: {}", ip, e);
                            self.metrics.increment_errors().await;
                        }
                        
                        // Store MAC address and vendor information if available
                        if mac_address.is_some() || vendor.is_some() {
                            if let Err(e) = self.store_host_network_info(ip, mac_address, vendor).await {
                                eprintln!("Failed to store network info for host {}: {}", ip, e);
                                self.metrics.increment_errors().await;
                            }
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
                        let service = observation.fields.get("service").and_then(|v| v.as_str());
                        let version = observation.fields.get("version").and_then(|v| v.as_str());
                        let banner = observation.fields.get("banner").and_then(|v| v.as_str());
                        
                        if let Err(e) = self.store_service_detailed(ip, port, protocol, state, service, version, banner).await {
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
