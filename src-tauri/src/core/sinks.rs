use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use crate::shared::types;
use crate::analysis::vulnerability::VulnerabilityEngine;
use crate::shared::traits::Sink;
use crate::database::Db;
use crate::shared::shared::{ObsStream, ObservationKind};

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

    /// Emit a host event if not already cached or if it has enhanced data
    async fn emit_host_with_enrichment(
        &self,
        ip: &str,
        hostname: Option<String>,
        mac: Option<String>,
        vendor: Option<String>,
        os: Option<String>,
        status: String,
    ) -> Result<()> {
        let mut cache = self.host_cache.lock().await;
        let should_emit = !cache.contains_key(ip) || mac.is_some() || vendor.is_some() || os.is_some();

        if should_emit {
            let host_event = HostEvent {
                ip: ip.to_string(),
                hostname,
                mac,
                vendor,
                os,
                status,
                timestamp: Utc::now().to_rfc3339(),
            };

            log::info!("Emitting obs:host event for: {} (mac={:?}, vendor={:?}, os={:?})",
                host_event.ip, host_event.mac, host_event.vendor, host_event.os);
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

    /// Emit a host event if not already cached (backward compatibility)
    async fn emit_host_if_new(
        &self,
        ip: &str,
        hostname: Option<String>,
        _has_enhanced_data: bool,
    ) -> Result<()> {
        self.emit_host_with_enrichment(ip, hostname, None, None, None, "up".to_string()).await
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
                    // Port can be stored as either string or number, handle both
                    let port = obs.fields.get("port")
                        .and_then(|v| {
                            // Try as number first
                            if let Some(num) = v.as_u64() {
                                Some(num as u16)
                            } else if let Some(s) = v.as_str() {
                                // Try parsing string as number
                                s.parse::<u16>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
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

                    // Emit host first if new
                    self.emit_host_if_new(ip, None, false).await?;

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

                    let status = obs
                        .fields
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("up")
                        .to_string();

                    // Extract MAC address and vendor (from MacEnrichmentTransform or netsniffer)
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

                    // Extract OS information (from nmap, passive detection, or netsniffer)
                    let os_name = obs.fields.get("os_name").and_then(|v| v.as_str())
                        .or_else(|| obs.fields.get("passive_os").and_then(|v| v.as_str()))
                        .map(|s| s.to_string());

                    // Only emit hosts that are actually up (filter out down hosts)
                    if status == "up" {
                        log::debug!("Emitting host {} with status: {}", ip, status);
                        self.emit_host_with_enrichment(
                            ip,
                            hostname.clone(),
                            mac.clone(),
                            vendor.clone(),
                            os_name.clone(),
                            status.clone()
                        ).await?;
                    } else {
                        log::debug!("Skipping host {} - status is '{}'", ip, status);
                    }

                    // Build detailed progress message with all enriched data
                    let mut details = Vec::new();
                    if let Some(hn) = &hostname {
                        details.push(format!("hostname: {}", hn));
                    }
                    if let Some(v) = &vendor {
                        details.push(format!("vendor: {}", v));
                    }
                    if let Some(os) = &os_name {
                        details.push(format!("OS: {}", os));
                    }
                    if let Some(ttl) = obs.fields.get("ttl").and_then(|v| v.as_u64()) {
                        details.push(format!("TTL: {}", ttl));
                    }

                    let progress_msg = if details.is_empty() {
                        format!("Host discovered: {} - {}", ip, status)
                    } else {
                        format!("Host discovered: {} - {} [{}]", ip, status, details.join(", "))
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
    nic_vendor: Option<String>,
    nic_model: Option<String>,
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
    product: Option<String>,
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
    hosts_in_batch: Arc<Mutex<HashSet<String>>>,
    hosts_in_db: Arc<Mutex<HashSet<String>>>,
}

impl DbSink {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            metrics: SinkMetrics::new(),
            hosts_in_batch: Arc::new(Mutex::new(HashSet::new())),
            hosts_in_db: Arc::new(Mutex::new(HashSet::new())),
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
        vulnerability: &crate::shared::types::Vulnerability,
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
                                        "Found {} vulnerabilities for {}:{}",
                                        vulnerabilities.len(),
                                        ip,
                                        port
                                    );

                                    if vulnerabilities.is_empty() {
                                        log::debug!(
                                            "No vulnerabilities found for {}:{} ({})",
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
        self.db
            .upsert_host(ip, hostname, status, None, None, None, None, None)
            .await?;
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
            .update_host_network_info(ip, mac_address, vendor, None)
            .await?;
        Ok(())
    }

    #[allow(dead_code)] // Utility method for future use
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
        product: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Result<()> {
        self.db
            .upsert_service_detailed(ip, port, protocol, Some(state), service, product, version, banner)
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

    #[allow(dead_code)] // Utility method for future use
    async fn store_host_hostname(&self, ip: &str, hostname: Option<&str>) -> Result<()> {
        if let Some(hostname) = hostname {
            self.db
                .update_host_info(ip, Some(hostname), None, None)
                .await?;
        }
        Ok(())
    }

    /// Ensure host exists in database before storing services
    /// Checks both batch tracking and confirmed DB tracking
    async fn ensure_host_exists(&self, ip: &str) -> Result<()> {
        // Check if host is already in batch or confirmed in DB (read-only check)
        let batch_set = self.hosts_in_batch.lock().await;
        let db_set = self.hosts_in_db.lock().await;
        
        if batch_set.contains(ip) || db_set.contains(ip) {
            return Ok(());
        }
        
        // Drop read locks before acquiring write lock
        drop(batch_set);
        drop(db_set);
        
        // Host not in batch or DB - store immediately
        log::debug!("Ensuring host {} exists in database before service storage", ip);
        self.store_host(ip, None, Some("up")).await?;
        
        // Update tracking set after storing
        let mut db_set = self.hosts_in_db.lock().await;
        db_set.insert(ip.to_string());
        log::debug!("Host {} stored and added to tracking set", ip);
        
        Ok(())
    }

    /// Batch insert hosts with direct async calls for performance
    async fn flush_hosts_batch(&self, batch: &[HostBatchItem]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        log::debug!("Flushing batch of {} hosts to database", batch.len());
        let batch_items = batch.to_vec();

        for item in &batch_items {
            log::debug!("Storing host {}", item.ip);
            // Store basic host info first
            if let Err(e) = self.store_host(&item.ip, item.hostname.as_deref(), item.status.as_deref()).await {
                log::error!("Failed to batch store host {}: {}", item.ip, e);
                continue;
            }
            
            // Update with network info if available
            if item.mac_address.is_some() || item.nic_vendor.is_some() {
                if let Err(e) = self.store_host_network_info(
                    &item.ip,
                    item.mac_address.as_deref(),
                    item.nic_vendor.as_deref(),
                ).await {
                    log::warn!("Failed to update network info for host {}: {}", item.ip, e);
                }
            }
            
            // Update with OS info if available
            if item.os_name.is_some() || item.os_family.is_some() {
                if let Err(e) = self.store_host_os_info(
                    &item.ip,
                    item.os_name.as_deref(),
                    item.os_family.as_deref(),
                    item.os_accuracy,
                ).await {
                    log::warn!("Failed to update OS info for host {}: {}", item.ip, e);
                }
            }
            
            log::debug!("Successfully stored host {}", item.ip);
        }

        log::info!("Batch processed {} hosts", batch.len());
        Ok(())
    }

    /// Batch insert services with direct async calls for performance
    async fn flush_services_batch(&self, batch: &[ServiceBatchItem]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        log::debug!("Flushing batch of {} services to database", batch.len());

        let batch_items = batch.to_vec();

        // Collect unique IPs to update port counts only once per host
        let mut unique_ips = std::collections::HashSet::new();

        for item in &batch_items {
            log::debug!("Storing service {}:{}:{}", item.ip, item.port, item.protocol);
            
            // Use store_service_detailed method
            if let Err(e) = self
                .store_service_detailed(
                    &item.ip,
                    item.port,
                    &item.protocol,
                    &item.state,
                    item.service.as_deref(),
                    item.product.as_deref(),
                    item.version.as_deref(),
                    item.banner.as_deref(),
                )
                .await
            {
                log::error!(
                    "Failed to batch store service {}:{}: {}",
                    item.ip,
                    item.port,
                    e
                );
            } else {
                log::debug!("Successfully stored service {}:{}:{}", item.ip, item.port, item.protocol);
                unique_ips.insert(item.ip.clone());
            }
        }

        // Update port counts once per host after all services are inserted
        for ip in unique_ips {
            if let Err(e) = self.db.update_host_port_count(&ip).await {
                log::error!(
                    "Failed to update port count for {} after batch: {}",
                    ip,
                    e
                );
            } else {
                log::debug!("Updated port count for host {}", ip);
            }
        }
        Ok(())
    }

    /// Batch insert vulnerabilities with direct async calls for performance
    async fn flush_vulnerabilities_batch(&self, batch: &[VulnerabilityBatchItem]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        log::debug!("Flushing batch of {} vulnerabilities to database", batch.len());
        let batch_items = batch.to_vec();

        for item in &batch_items {
            log::debug!("Storing vulnerability {} for host {}:{}", item.name, item.host_ip, item.port);
            
            if let Err(e) = self.db.store_vulnerability(
                &item.id,
                &item.host_ip,
                item.port,
                &item.name,
                &item.description,
                &item.severity,
                item.cvss_score,
                item.cve_id.as_deref(),
                None, // remediation not stored in batch item
            ).await {
                log::error!(
                    "Failed to batch store vulnerability {} for {}:{}: {}",
                    item.name,
                    item.host_ip,
                    item.port,
                    e
                );
            } else {
                log::debug!("Successfully stored vulnerability {} for {}:{}", item.name, item.host_ip, item.port);
            }
        }

        log::info!("Batch processed {} vulnerabilities", batch.len());
        Ok(())
    }

    /// Flush entire batch to database
    async fn flush_batch(&self, batch: &mut ObsBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let start_time = std::time::Instant::now();

        // Flush hosts first to ensure they exist before inserting ports (foreign key constraint)
        if let Err(e) = self.flush_hosts_batch(&batch.hosts).await {
            log::error!("Host batch flush failed: {}", e);
            // Don't flush services if hosts failed - they may have foreign key dependencies
            batch.clear();
            return Err(e);
        }

        // Move successfully flushed hosts from batch tracking to DB tracking
        {
            let mut batch_set = self.hosts_in_batch.lock().await;
            let mut db_set = self.hosts_in_db.lock().await;
            for host in &batch.hosts {
                db_set.insert(host.ip.clone());
                batch_set.remove(&host.ip);
            }
        }

        // Flush services after hosts are successfully inserted
        if let Err(e) = self.flush_services_batch(&batch.services).await {
            log::error!("Service batch flush failed: {}", e);
            // Continue even if services fail - hosts are already stored
        }

        // Flush vulnerabilities after hosts and services (vulnerabilities reference hosts/ports)
        if let Err(e) = self.flush_vulnerabilities_batch(&batch.vulnerabilities).await {
            log::error!("Vulnerability batch flush failed: {}", e);
            // Continue even if vulnerabilities fail - hosts and services are already stored
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
                                        let status_str = observation.fields.get("status").and_then(|v| v.as_str()).unwrap_or("up");

                                        // Only store hosts that are actually up (skip down hosts)
                                        if status_str != "up" {
                                            log::debug!("DbSink: Skipping host {} - status is '{}'", ip, status_str);
                                            continue;
                                        }

                                        let status = Some(status_str.to_string());
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
                                            nic_vendor: vendor,
                                            nic_model: None,
                                            os_name,
                                            os_family,
                                            os_accuracy,
                                        });
                                        
                                        // Track host in batch
                                        let mut batch_set = self.hosts_in_batch.lock().await;
                                        batch_set.insert(ip.to_string());
                                    }
                                }
                                ObservationKind::Service => {
                                    log::debug!("Received service observation: {:?}", observation.fields);
                                    
                                    // Parse port from either string or number
                                    let port_opt = observation.fields.get("port")
                                        .and_then(|v| {
                                            // Try as number first
                                            if let Some(num) = v.as_u64() {
                                                log::debug!("Extracted port as number: {}", num);
                                                Some(num as u16)
                                            } else if let Some(s) = v.as_str() {
                                                // Try parsing string as number
                                                if let Ok(parsed) = s.parse::<u16>() {
                                                    log::debug!("Extracted port from string '{}': {}", s, parsed);
                                                    Some(parsed)
                                                } else {
                                                    log::warn!("Failed to parse port string '{}' as u16", s);
                                                    None
                                                }
                                            } else {
                                                log::warn!("Port field is neither number nor string: {:?}", v);
                                                None
                                            }
                                        });

                                    if let (Some(ip), Some(port), Some(protocol)) = (
                                        observation.fields.get("ip").and_then(|v| v.as_str()),
                                        port_opt,
                                        observation.fields.get("protocol").and_then(|v| v.as_str()),
                                    ) {
                                        // Ensure host exists before adding service to batch
                                        if let Err(e) = self.ensure_host_exists(ip).await {
                                            log::error!("Failed to ensure host {} exists: {}", ip, e);
                                            self.metrics.increment_errors().await;
                                            continue;
                                        }
                                        
                                        let state = observation.fields.get("state").and_then(|v| v.as_str()).unwrap_or("open");
                                        let service = observation.fields.get("service").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let product = observation.fields.get("product").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let version = observation.fields.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let banner = observation.fields.get("banner").and_then(|v| v.as_str())
                                            .or_else(|| observation.fields.get("extrainfo").and_then(|v| v.as_str()))
                                            .map(|s| s.to_string());

                                        log::debug!("Adding service to batch: {}:{}:{} (state: {}, service: {:?}, product: {:?})", 
                                                   ip, port, protocol, state, service, product);

                                        batch.add_service(ServiceBatchItem {
                                            ip: ip.to_string(),
                                            port,
                                            protocol: protocol.to_string(),
                                            state: state.to_string(),
                                            service,
                                            version,
                                            banner,
                                            product,
                                        });
                                        
                                        log::debug!("Service added to batch successfully");
                                    } else {
                                        log::warn!("Missing required fields for service observation - ip: {:?}, port: {:?}, protocol: {:?}",
                                                  observation.fields.get("ip"),
                                                  port_opt,
                                                  observation.fields.get("protocol"));
                                    }
                                }
                                ObservationKind::Error => {
                                    if let Some(message) = observation.fields.get("message").and_then(|v| v.as_str()) {
                                        log::error!("Database sink encountered scan error: {}", message);
                                        self.metrics.increment_errors().await;
                                    }
                                }
                                _ => {
                                    // Check if observation contains vulnerability data
                                    if let (Some(id), Some(host_ip), Some(name), Some(severity), Some(description)) = (
                                        observation.fields.get("vulnerability_id").or_else(|| observation.fields.get("id")).and_then(|v| v.as_str()),
                                        observation.fields.get("host_ip").or_else(|| observation.fields.get("ip")).and_then(|v| v.as_str()),
                                        observation.fields.get("vulnerability_name").or_else(|| observation.fields.get("name")).and_then(|v| v.as_str()),
                                        observation.fields.get("severity").and_then(|v| v.as_str()),
                                        observation.fields.get("description").and_then(|v| v.as_str()),
                                    ) {
                                        // Extract port (optional for vulnerabilities)
                                        let port = observation.fields.get("port")
                                            .and_then(|v| {
                                                if let Some(num) = v.as_u64() {
                                                    Some(num as u16)
                                                } else if let Some(s) = v.as_str() {
                                                    s.parse::<u16>().ok()
                                                } else {
                                                    None
                                                }
                                            })
                                            .unwrap_or(0);
                                        
                                        let cvss_score = observation.fields.get("cvss_score").and_then(|v| v.as_f64()).map(|s| s as f32);
                                        let cve_id = observation.fields.get("cve_id").or_else(|| observation.fields.get("cve")).and_then(|v| v.as_str()).map(|s| s.to_string());
                                        
                                        log::debug!("Adding vulnerability to batch: {} for host {}:{}", name, host_ip, port);
                                        
                                        batch.add_vulnerability(VulnerabilityBatchItem {
                                            id: id.to_string(),
                                            host_ip: host_ip.to_string(),
                                            port,
                                            name: name.to_string(),
                                            description: description.to_string(),
                                            severity: severity.to_string(),
                                            cvss_score,
                                            cve_id,
                                        });
                                    }
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
