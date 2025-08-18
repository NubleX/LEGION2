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

use crate::analysis::vulnerability::VulnerabilityEngine;
use crate::core::traits::Sink;
use crate::database::Db;
use crate::shared::{ObsStream, ObservationKind};

// Event structures for frontend communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEvent {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub os: Option<String>,
    pub status: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub reason: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub vulnerabilities: Option<serde_json::Value>,
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
                mac: None,
                vendor: None,
                os: None,
                status: "up".to_string(),
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

                // Also emit a signal to refresh host data from database
                if let Err(e) = self.app.emit("refresh_host_data", &ip) {
                    log::warn!("Failed to emit refresh_host_data event: {}", e);
                }
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
            service: None,
            product: None,
            version: None,
            vulnerabilities: None,
            timestamp: Utc::now().to_rfc3339(),
        };

        log::info!(
            "Emitting obs:service event for: {}:{}/{}",
            service_event.ip,
            service_event.port,
            service_event.protocol
        );
        if let Err(e) = self.app.emit("obs:service", &service_event) {
            log::error!("Failed to emit obs:service event: {}", e);
            self.metrics.increment_errors().await;
        } else {
            log::debug!(
                "Successfully emitted obs:service event for {}:{}",
                service_event.ip,
                service_event.port
            );
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
                    let service = obs
                        .fields
                        .get("service")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let version = obs
                        .fields
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    // Create detailed service description
                    let service_desc = if !service.is_empty() && !version.is_empty() {
                        format!("{} {}", service, version)
                    } else if !service.is_empty() {
                        service.to_string()
                    } else {
                        "unknown".to_string()
                    };

                    // Extract rich service information
                    let service = obs
                        .fields
                        .get("service")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let product = obs
                        .fields
                        .get("product")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let service_version = obs
                        .fields
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let vulnerabilities = obs.fields.get("vulnerabilities");

                    // Emit comprehensive service event with all rich data
                    let service_event = ServiceEvent {
                        ip: ip.to_string(),
                        port,
                        protocol: protocol.to_string(),
                        reason: _reason.to_string(),
                        service: service.clone(),
                        product: product.clone(),
                        version: service_version.clone(),
                        vulnerabilities: vulnerabilities.cloned(),
                        timestamp: Utc::now().to_rfc3339(),
                    };

                    log::info!(
                        "Emitting comprehensive obs:service event for: {}:{}/{}",
                        service_event.ip,
                        service_event.port,
                        service_event.protocol
                    );
                    if let Err(e) = self.app.emit("obs:service", &service_event) {
                        log::error!("Failed to emit obs:service event: {}", e);
                        self.metrics.increment_errors().await;
                    } else {
                        self.metrics.increment_services().await;
                    }

                    // Emit host first if new (for proper hierarchy)
                    self.emit_host_if_new(ip, None).await?;

                    // Also emit as progress to show in live output
                    let progress_msg = format!(
                        "Found service: {}:{}/{} - {}",
                        ip, port, protocol, service_desc
                    );
                    self.emit_progress(&progress_msg, None).await?;
                }
                ObservationKind::Host => {
                    // Extract comprehensive host information for rich UI
                    let ip = obs
                        .fields
                        .get("ip")
                        .or_else(|| obs.fields.get("ipv4"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let hostname = obs
                        .fields
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let mac = obs
                        .fields
                        .get("mac_address")
                        .or_else(|| obs.fields.get("mac"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let vendor = obs
                        .fields
                        .get("vendor")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let os = obs
                        .fields
                        .get("os_name")
                        .or_else(|| obs.fields.get("os"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let status = obs
                        .fields
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("up");

                    // Emit comprehensive host event with all rich data
                    let host_event = HostEvent {
                        ip: ip.to_string(),
                        hostname: hostname.clone(),
                        mac: mac.clone(),
                        vendor: vendor.clone(),
                        os: os.clone(),
                        status: status.to_string(),
                        timestamp: Utc::now().to_rfc3339(),
                    };

                    log::info!(
                        "Emitting comprehensive obs:host event for: {}",
                        host_event.ip
                    );
                    if let Err(e) = self.app.emit("obs:host", &host_event) {
                        log::error!("Failed to emit obs:host event: {}", e);
                        self.metrics.increment_errors().await;
                    } else {
                        self.metrics.increment_hosts().await;

                        // Also emit refresh signal for database sync
                        if let Err(e) = self.app.emit("refresh_host_data", &ip) {
                            log::warn!("Failed to emit refresh_host_data event: {}", e);
                        }
                    }

                    // Also emit as progress to show in live output with rich details
                    let progress_msg = if let Some(ref hn) = hostname {
                        if let Some(ref os_info) = os {
                            format!(
                                "Host discovered: {} ({}) - {} [{}]",
                                ip, hn, status, os_info
                            )
                        } else {
                            format!("Host discovered: {} ({}) - {}", ip, hn, status)
                        }
                    } else if let Some(ref os_info) = os {
                        format!("Host discovered: {} - {} [{}]", ip, status, os_info)
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
    hosts: Vec<HostBatchItem>,
    services: Vec<ServiceBatchItem>,
    vulnerabilities: Vec<VulnerabilityBatchItem>,
}

#[derive(Debug, Clone)]
struct HostBatchItem {
    ip: String,
    hostname: Option<String>,
    status: Option<String>,
    mac_address: Option<String>,
    vendor: Option<String>,
    os_name: Option<String>,
    os_family: Option<String>,
    os_accuracy: Option<f32>,
}

#[derive(Debug, Clone)]
struct ServiceBatchItem {
    ip: String,
    port: u16,
    protocol: String,
    state: String,
    service: Option<String>,
    version: Option<String>,
    banner: Option<String>,
}

#[derive(Debug, Clone)]
struct VulnerabilityBatchItem {
    id: String,
    host_ip: String,
    port: u16,
    name: String,
    description: String,
    severity: String,
    cvss_score: Option<f32>,
    cve_id: Option<String>,
}

impl ObsBatch {
    fn new() -> Self {
        Self {
            hosts: Vec::new(),
            services: Vec::new(),
            vulnerabilities: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.services.is_empty() && self.vulnerabilities.is_empty()
    }

    fn len(&self) -> usize {
        self.hosts.len() + self.services.len() + self.vulnerabilities.len()
    }

    fn clear(&mut self) {
        self.hosts.clear();
        self.services.clear();
        self.vulnerabilities.clear();
    }

    fn add_host(&mut self, item: HostBatchItem) {
        self.hosts.push(item);
    }

    fn add_service(&mut self, item: ServiceBatchItem) {
        self.services.push(item);
    }

    fn add_vulnerability(&mut self, item: VulnerabilityBatchItem) {
        self.vulnerabilities.push(item);
    }

    fn should_flush(&self) -> bool {
        self.len() >= 50 // Flush when we have 50+ items
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

    async fn emit_vulnerability(
        &self,
        vulnerability: &crate::analysis::types::Vulnerability,
    ) -> Result<()> {
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
            cve_id: Option<String>,
            timestamp: String,
        }

        let vuln_event = VulnerabilityEvent {
            id: vulnerability.finding.id.clone(),
            host_ip: vulnerability.finding.host.clone(),
            port: vulnerability.finding.port.unwrap_or(0),
            service: vulnerability
                .finding
                .service
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            name: vulnerability.finding.title.clone(),
            severity: format!("{:?}", vulnerability.finding.severity),
            description: vulnerability.finding.description.clone(),
            cvss_score: vulnerability.cvss_score,
            cve_id: vulnerability.cve_id.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        if let Err(e) = self.app.emit("obs:vulnerability", &vuln_event) {
            log::error!("Failed to emit vulnerability event: {}", e);
        } else {
            log::info!(
                "📢 Emitted vulnerability event: {} for {}:{}",
                vuln_event.name,
                vuln_event.host_ip,
                vuln_event.port
            );

            // Also emit as progress message for live output
            let progress_msg = format!(
                "🔍 Vulnerability found: {} on {}:{} - {} ({})",
                vulnerability.finding.title,
                vulnerability.finding.host,
                vulnerability.finding.port.unwrap_or(0),
                vulnerability
                    .finding
                    .service
                    .as_deref()
                    .unwrap_or("unknown"),
                format!("{:?}", vulnerability.finding.severity)
            );

            if let Err(e) = self.app.emit(
                "obs:progress",
                &ProgressEvent {
                    message: progress_msg,
                    percentage: None,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                },
            ) {
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
        log::info!("🔍 VulnerabilityAnalysisSink started - listening for service observations");
        let mut services_analyzed = 0u64;
        let mut vulnerabilities_found = 0u64;

        while let Some(obs) = input.next().await {
            self.metrics.increment_observations().await;

            match obs.kind {
                ObservationKind::Service => {
                    // Extract service information
                    if let (Some(ip), Some(port)) = (
                        obs.fields.get("ip").and_then(|v| v.as_str()),
                        obs.fields
                            .get("port")
                            .and_then(|v| v.as_u64())
                            .map(|p| p as u16),
                    ) {
                        let service = obs.fields.get("service").and_then(|v| v.as_str());
                        let version = obs.fields.get("version").and_then(|v| v.as_str());
                        let banner = obs.fields.get("banner").and_then(|v| v.as_str());
                        let state = obs
                            .fields
                            .get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("open");

                        // Only analyze open services
                        if state.to_lowercase() == "open" {
                            services_analyzed += 1;
                            let service_name = service.unwrap_or("unknown");

                            log::info!(
                                "🔍 Analyzing service {}:{}/{} ({})",
                                ip,
                                port,
                                state,
                                service_name
                            );

                            // Run vulnerability analysis on this service
                            match self
                                .vulnerability_engine
                                .analyze_service(ip, port, service_name, version, banner)
                                .await
                            {
                                Ok(vulnerabilities) => {
                                    log::info!(
                                        "✅ Found {} vulnerabilities for {}:{}",
                                        vulnerabilities.len(),
                                        ip,
                                        port
                                    );

                                    if vulnerabilities.is_empty() {
                                        log::debug!(
                                            "✅ No vulnerabilities found for {}:{} ({})",
                                            ip,
                                            port,
                                            service_name
                                        );
                                    } else {
                                        vulnerabilities_found += vulnerabilities.len() as u64;

                                        for vuln in vulnerabilities {
                                            log::info!(
                                                "🚨 Emitting vulnerability: {} for {}:{}",
                                                vuln.finding.title,
                                                ip,
                                                port
                                            );
                                            if let Err(e) = self.emit_vulnerability(&vuln).await {
                                                log::error!(
                                                    "❌ Failed to emit vulnerability: {}",
                                                    e
                                                );
                                                self.metrics.increment_errors().await;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!(
                                        "❌ Vulnerability analysis failed for {}:{} ({}): {}",
                                        ip,
                                        port,
                                        service_name,
                                        e
                                    );
                                    self.metrics.increment_errors().await;
                                }
                            }
                        } else {
                            log::debug!("⏭️  Skipping non-open service {}:{}/{}", ip, port, state);
                        }
                    } else {
                        log::warn!("⚠️  Service observation missing required fields (ip or port)");
                    }
                }
                _ => {
                    // Don't process other observation types for vulnerability analysis
                    log::trace!("⏭️  Skipping non-service observation: {:?}", obs.kind);
                }
            }
        }

        log::info!("🔍 VulnerabilityAnalysisSink completed: analyzed {} services, found {} vulnerabilities", 
                  services_analyzed, vulnerabilities_found);
        Ok(())
    }
}

impl DbSink {
    async fn store_host(
        &self,
        ip: &str,
        hostname: Option<&str>,
        status: Option<&str>,
    ) -> Result<()> {
        self.db.upsert_host(ip, hostname, status).await?;
        self.metrics.increment_hosts().await;
        Ok(())
    }

    async fn store_host_network_info(
        &self,
        ip: &str,
        mac_address: Option<&str>,
        vendor: Option<&str>,
    ) -> Result<()> {
        self.db
            .update_host_network_info(ip, mac_address, vendor)
            .await?;
        Ok(())
    }

    async fn store_service(&self, ip: &str, port: u16, protocol: &str, state: &str) -> Result<()> {
        self.db
            .upsert_service(ip, port, protocol, Some(state))
            .await?;
        self.metrics.increment_services().await;
        Ok(())
    }

    async fn store_service_detailed(
        &self,
        ip: &str,
        port: u16,
        protocol: &str,
        state: &str,
        service: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Result<()> {
        self.db
            .upsert_service_detailed(ip, port, protocol, Some(state), service, version, banner)
            .await?;
        self.metrics.increment_services().await;
        Ok(())
    }

    async fn store_host_os_info(
        &self,
        ip: &str,
        os_name: Option<&str>,
        os_family: Option<&str>,
        os_accuracy: Option<f32>,
    ) -> Result<()> {
        self.db
            .update_host_os(ip, os_name, os_family, os_accuracy)
            .await?;
        Ok(())
    }

    async fn store_host_hostname(&self, ip: &str, hostname: Option<&str>) -> Result<()> {
        if let Some(hostname) = hostname {
            self.db
                .update_host_info(ip, Some(hostname), None, None)
                .await?;
        }
        Ok(())
    }

    /// Batch insert hosts with spawn_blocking for performance
    async fn flush_hosts_batch(&self, batch: &[HostBatchItem]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let db = self.db.clone();
        let batch_items = batch.to_vec();

        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async {
                for item in batch_items {
                    // Store host with all information at once
                    if let Err(e) = db
                        .upsert_host(&item.ip, item.hostname.as_deref(), item.status.as_deref())
                        .await
                    {
                        log::error!("Failed to batch store host {}: {}", item.ip, e);
                        continue;
                    }

                    // Store network info if available
                    if item.mac_address.is_some() || item.vendor.is_some() {
                        if let Err(e) = db
                            .update_host_network_info(
                                &item.ip,
                                item.mac_address.as_deref(),
                                item.vendor.as_deref(),
                            )
                            .await
                        {
                            log::error!(
                                "Failed to batch store network info for {}: {}",
                                item.ip,
                                e
                            );
                        }
                    }

                    // Store OS info if available
                    if item.os_name.is_some()
                        || item.os_family.is_some()
                        || item.os_accuracy.is_some()
                    {
                        if let Err(e) = db
                            .update_host_os(
                                &item.ip,
                                item.os_name.as_deref(),
                                item.os_family.as_deref(),
                                item.os_accuracy,
                            )
                            .await
                        {
                            log::error!("Failed to batch store OS info for {}: {}", item.ip, e);
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        })
        .await??;

        log::debug!("Batch processed {} hosts", batch.len());
        Ok(())
    }

    /// Batch insert services with spawn_blocking for performance
    async fn flush_services_batch(&self, batch: &[ServiceBatchItem]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let db = self.db.clone();
        let batch_items = batch.to_vec();

        
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async {
                for item in batch_items {
                    if let Err(e) = db
                        .upsert_service_detailed(
                            &item.ip,
                            item.port,
                            &item.protocol,
                            Some(&item.state),
                            item.service.as_deref(),
                            item.version.as_deref(),
                            item.banner.as_deref(),
                        )
                        .await
                    {
                        log::error!("Failed to batch store service {}:{}: {}", item.ip, item.port, e);
                    } else if let Err(e) = db.update_host_port_count(&item.ip).await {
                        log::error!(
                            "Failed to update port count for {} after service insert: {}",
                            item.ip,
                            e
                        );
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        }).await??;

        log::debug!("Batch processed {} services", batch.len());
        Ok(())
    }

    /// Flush entire batch to database
    async fn flush_batch(&self, batch: &mut ObsBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let start_time = std::time::Instant::now();

        // Process batches concurrently
        let hosts_task = self.flush_hosts_batch(&batch.hosts);
        let services_task = self.flush_services_batch(&batch.services);

        // Wait for all batch operations to complete
        let (hosts_result, services_result) = tokio::join!(hosts_task, services_task);

        if let Err(e) = hosts_result {
            log::error!("Host batch flush failed: {}", e);
        }
        if let Err(e) = services_result {
            log::error!("Service batch flush failed: {}", e);
        }

        let duration = start_time.elapsed();
        log::info!(
            "Flushed batch of {} items in {}ms",
            batch.len(),
            duration.as_millis()
        );

        // Update metrics
        for _ in &batch.hosts {
            self.metrics.increment_hosts().await;
        }
        for _ in &batch.services {
            self.metrics.increment_services().await;
        }

        batch.clear();
        Ok(())
    }
}

#[async_trait]
impl Sink for DbSink {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn run(&self, mut stream: ObsStream) -> Result<()> {
        let mut batch = ObsBatch::new();
        let mut flush_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            tokio::select! {
                // Process observations
                obs_result = stream.next() => {
                    match obs_result {
                        Some(observation) => {
                            match observation.kind {
                                ObservationKind::Host => {
                                    if let Some(ip) = observation.fields.get("ip").and_then(|v| v.as_str()) {
                                        let hostname = observation.fields.get("hostname").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let status = observation.fields.get("status").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let mac_address = observation.fields.get("mac_address").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let vendor = observation.fields.get("vendor").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let os_name = observation.fields.get("os_name").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let os_family = observation.fields.get("os_family").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let os_accuracy = observation.fields.get("os_accuracy").and_then(|v| v.as_f64()).map(|a| a as f32);

                                        batch.add_host(HostBatchItem {
                                            ip: ip.to_string(),
                                            hostname,
                                            status,
                                            mac_address,
                                            vendor,
                                            os_name,
                                            os_family,
                                            os_accuracy,
                                        });
                                    }
                                }
                                ObservationKind::Service => {
                                    if let (Some(ip), Some(port), Some(protocol)) = (
                                        observation.fields.get("ip").and_then(|v| v.as_str()),
                                        observation.fields.get("port").and_then(|v| v.as_u64()).map(|p| p as u16),
                                        observation.fields.get("protocol").and_then(|v| v.as_str()),
                                    ) {
                                        let state = observation.fields.get("state").and_then(|v| v.as_str()).unwrap_or("open");
                                        let service = observation.fields.get("service").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let version = observation.fields.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let banner = observation.fields.get("banner").and_then(|v| v.as_str()).map(|s| s.to_string());

                                        batch.add_service(ServiceBatchItem {
                                            ip: ip.to_string(),
                                            port,
                                            protocol: protocol.to_string(),
                                            state: state.to_string(),
                                            service,
                                            version,
                                            banner,
                                        });
                                    }
                                }
                                ObservationKind::Error => {
                                    if let Some(message) = observation.fields.get("message").and_then(|v| v.as_str()) {
                                        log::error!("Database sink encountered scan error: {}", message);
                                        self.metrics.increment_errors().await;
                                    }
                                }
                                _ => {
                                    // Other observation types don't need DB storage
                                }
                            }

                            self.metrics.increment_observations().await;

                            // Flush batch if it's getting large
                            if batch.should_flush() {
                                if let Err(e) = self.flush_batch(&mut batch).await {
                                    log::error!("Failed to flush observation batch: {}", e);
                                    self.metrics.increment_errors().await;
                                }
                            }
                        }
                        None => {
                            // Stream ended, flush remaining batch and exit
                            if !batch.is_empty() {
                                if let Err(e) = self.flush_batch(&mut batch).await {
                                    log::error!("Failed to flush final batch: {}", e);
                                }
                            }
                            break;
                        }
                    }
                }

                // Periodic flush every 5 seconds to ensure data freshness
                _ = flush_interval.tick() => {
                    if !batch.is_empty() {
                        if let Err(e) = self.flush_batch(&mut batch).await {
                            log::error!("Failed to flush periodic batch: {}", e);
                            self.metrics.increment_errors().await;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
