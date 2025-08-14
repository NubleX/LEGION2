// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.
// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security
//     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
//     License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
//     version.
//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
//     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//     details.
//     You should have received a copy of the GNU General Public License along with this program.
//     If not, see <http://www.gnu.org/licenses/>.

use anyhow::Result;
use chrono::Utc;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::database::DatabaseOperations;
use crate::commands::scanner_commands::ScanTarget;
use crate::scanning::{
    events::{EventType, ScanEvent},
    masscan::MasscanScanner,
    models::{ScanProgress, ScanResult, ScanStatistics, ScanType},
    nmap::{NmapScanner, ScanResult as NmapScanResult},
};
use crate::shared::{Host, HostStatus};

#[derive(Debug, Clone)]
pub struct ScanHandle {
    pub cancel_tx: mpsc::Sender<()>,
    pub status: Arc<tokio::sync::Mutex<CoordinatorScanStatus>>,
}

#[derive(Debug, Clone)]
pub enum CoordinatorScanStatus {
    Running,
    Failed(String),
    Completed,
}

pub struct ScanCoordinator {
    database: Arc<DatabaseOperations>,
    active_scans: Arc<RwLock<HashMap<Uuid, ScanHandle>>>,
    results_tx: mpsc::Sender<ScanEvent>,
    nmap_scanner: Arc<NmapScanner>,
    masscan_scanner: Arc<MasscanScanner>,
}

impl ScanCoordinator {
    pub fn borrow(database: Arc<DatabaseOperations>, results_tx: mpsc::Sender<ScanEvent>) -> Self {
        Self {
            database,
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            results_tx,
            nmap_scanner: Arc::new(NmapScanner::new()),
            masscan_scanner: Arc::new(
                MasscanScanner::new().expect("Failed to initialize MasscanScanner"),
            ),
        }
    }

    pub async fn start_scan(&self, target: ScanTarget) -> Result<Uuid> {
        let scan_id = Uuid::new_v4();
        log::info!(
            "Starting scan for target: {:?} with ID: {}",
            target,
            scan_id
        );

        let (cancel_tx, cancel_rx) = mpsc::channel(1);
        let (progress_tx, progress_rx) = mpsc::channel(100);

        // Initialize scan
        self.initialize_scan(scan_id, &target, cancel_tx).await?;

        // Spawn scan task
        self.spawn_scan_task(scan_id, target.clone(), cancel_rx, progress_tx)
            .await;

        // Monitor progress
        self.monitor_progress(scan_id, progress_rx);

        Ok(scan_id)
    }

    async fn initialize_scan(
        &self,
        scan_id: Uuid,
        target: &ScanTarget,
        cancel_tx: mpsc::Sender<()>,
    ) -> Result<()> {
        // TODO: Implement proper host creation
        log::info!("Starting scan for target: {}", target.ip);

        self.active_scans.write().await.insert(
            scan_id,
            ScanHandle {
                cancel_tx,
                status: Arc::new(tokio::sync::Mutex::new(CoordinatorScanStatus::Running)),
            },
        );

        Ok(())
    }

    async fn spawn_scan_task(
        &self,
        scan_id: Uuid,
        target: ScanTarget,
        mut cancel_rx: mpsc::Receiver<()>,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) {
        let scanner = self.nmap_scanner.clone();
        let active_scans = self.active_scans.clone();
        let results_tx = self.results_tx.clone();
        let database = self.database.clone();

        tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancel_rx.recv() => {
                    log::info!("Scan {} cancelled", scan_id);
                    Err(anyhow::anyhow!("Scan cancelled"))
                }
                scan_result = scanner.scan_target(&target, progress_tx, Some(results_tx.clone())) => {
                    scan_result
                }
            };

            Self::handle_scan_result(scan_id, result, database, results_tx).await;
            active_scans.write().await.remove(&scan_id);
        });
    }

    fn monitor_progress(&self, scan_id: Uuid, mut progress_rx: mpsc::Receiver<ScanProgress>) {
        let results_tx = self.results_tx.clone();

        tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                log::debug!("Scan {} progress: {}%", scan_id, progress.progress);
                let _ = results_tx
                    .send(ScanEvent {
                        scan_id: scan_id.to_string(),
                        event_type: EventType::ScanProgress,
                        timestamp: Utc::now(),
                        data: serde_json::json!(progress),
                    })
                    .await;
            }
        });
    }

    pub async fn cancel_scan(&self, scan_id: uuid::Uuid) -> Result<()> {
        let scans = self.active_scans.read().await;
        if let Some(handle) = scans.get(&scan_id) {
            let _ = handle.cancel_tx.send(()).await;
            let mut status = handle.status.lock().await;
            *status = CoordinatorScanStatus::Failed("Cancelled by user".to_string());
            Ok(())
        } else {
            Err(anyhow::anyhow!("Scan not found"))
        }
    }

    pub async fn scan_network_range(
        &self,
        cidr: &str,
        exclude: &[String],
        scan_type: ScanType,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<Vec<uuid::Uuid>> {
        let network: IpNet = cidr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid CIDR: {}", e))?;

        let exclude_ips: Vec<IpAddr> = exclude
            .iter()
            .filter_map(|ip| IpAddr::from_str(ip).ok())
            .collect();

        let mut scan_ids = Vec::new();
        let hosts: Vec<IpAddr> = network
            .hosts()
            .filter(|ip| !exclude_ips.contains(ip))
            .collect();

        let total_hosts = hosts.len();

        for (index, ip) in hosts.into_iter().enumerate() {
            let target = ScanTarget {
                id: uuid::Uuid::new_v4().to_string(),
                ip,
                hostname: None,
                ports: Some(Vec::new()),
                scan_type: scan_type.clone(),
            };

            match self.start_scan(target).await {
                Ok(scan_id) => {
                    scan_ids.push(scan_id);

                    // Send progress update
                    let now = Utc::now();
                    let progress_val = ((index + 1) as f32 / total_hosts as f32) * 100.0;
                    let _ = progress_tx
                        .send(ScanProgress {
                            scan_id: scan_id.to_string(),
                            status: crate::scanning::models::ScanStatus::Running,
                            percentage: progress_val,
                            stage: "Scanning hosts".to_string(),
                            targets_completed: index + 1,
                            targets_total: total_hosts,
                            hosts_found: index + 1,
                            services_found: 0,
                            eta_seconds: None,
                            started_at: now,
                            updated_at: now,
                            rate: None,
                            details: std::collections::HashMap::new(),
                            progress: progress_val,
                            current_target: Some(ip.to_string()),
                            hosts_discovered: (index + 1) as u32,
                            ports_found: 0,
                            vulnerabilities: 0,
                            elapsed_time: 0,
                            estimated_remaining: None,
                            message: Some("Scanning hosts".to_string()),
                            start_time: now,
                            current_phase: "host_discovery".to_string(),
                        })
                        .await;
                }
                Err(e) => {
                    log::error!("Failed to start scan for {}: {}", ip, e);
                }
            }
        }

        Ok(scan_ids)
    }

    pub async fn get_active_scans(&self) -> Vec<(uuid::Uuid, CoordinatorScanStatus)> {
        let scans = self.active_scans.read().await;
        let mut result = Vec::new();

        for (id, handle) in scans.iter() {
            let status = handle.status.lock().await;
            result.push((*id, status.clone()));
        }

        result
    }

    pub async fn get_scan_statistics(&self) -> ScanStatistics {
        let scans = self.active_scans.read().await;
        let active_count = scans.len() as u32;

        // query the database for more detailed stats
        ScanStatistics {
            scan_id: "global".to_string(),
            targets_scanned: 0,
            hosts_discovered: 0,
            services_discovered: 0,
            ports_scanned: 0,
            open_ports: 0,
            closed_ports: 0,
            filtered_ports: 0,
            avg_rate: 0.0,
            peak_rate: 0.0,
            total_time_seconds: 0,
            network_stats: None,
            total_scans: active_count,
            active_scans: active_count,
            completed_scans: 0,
            failed_scans: 0,
            total_hosts_discovered: 0,
            total_ports_found: 0,
            total_vulnerabilities: 0,
        }
    }

    async fn process_scan_result(
        &self,
        scan_result: &mut ScanResult,
    ) -> Result<crate::shared::Host> {
        // Get the first host from the scan results, or create a dummy one
        let first_host = scan_result.hosts.first();
        let target_ip = first_host
            .map(|h| h.ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Create host record
        let now = chrono::Utc::now();
        let host = Host {
            id: uuid::Uuid::new_v4().to_string(),
            ip: target_ip.clone(),
            hostname: first_host.and_then(|h| h.hostname.clone()),
            mac_address: first_host.and_then(|h| h.mac_address.clone()),
            vendor: None,
            os_name: first_host.and_then(|h| h.os.clone()),
            os_family: first_host.and_then(|h| h.os.clone()),
            os_accuracy: first_host.and_then(|h| h.os_confidence.map(|c| c * 100.0)),
            status: HostStatus::Up,
            last_seen: now,
            created_at: now,
            updated_at: now,
            port_count: scan_result.services.len() as i32,
            vulnerability_count: 0, // Would need to count vulnerabilities in discovered hosts
            notes: None,
            tags: Vec::new(),
            scan_progress: Some(100.0),
        };

        // Store host in database
        let _stored_host = self
            .database
            .upsert_host(&host.ip, host.hostname.as_deref())
            .await?;

        // Update OS detection if available (from first host)
        if let Some(first_host) = first_host {
            if let Some(os) = &first_host.os {
                self.database
                    .update_host_os(
                        &host.id,
                        Some(os),
                        Some(os),
                        Some(first_host.os_confidence.unwrap_or(0.0) * 100.0),
                    )
                    .await?;
            }
        }

        // Store service information as ports
        for service in &scan_result.services {
            // Convert protocol from models::Protocol to shared::Protocol
            let shared_protocol = match &service.protocol {
                crate::scanning::models::Protocol::Tcp => crate::shared::Protocol::Tcp,
                crate::scanning::models::Protocol::Udp => crate::shared::Protocol::Udp,
                _ => crate::shared::Protocol::Tcp, // Default to TCP for other protocols
            };

            // Convert state from String to PortState
            let port_state = service
                .state
                .parse::<crate::shared::PortState>()
                .unwrap_or(crate::shared::PortState::Unknown);

            if let Err(e) = self
                .database
                .add_port(
                    &host.id,
                    service.port,
                    match shared_protocol {
                        crate::shared::Protocol::Tcp => "tcp",
                        crate::shared::Protocol::Udp => "udp",
                    },
                    Some(match port_state {
                        crate::shared::PortState::Open => "open",
                        crate::shared::PortState::Closed => "closed",
                        crate::shared::PortState::Filtered => "filtered",
                        _ => "unknown",
                    }),
                    service.service.as_deref(),
                    None, // product not available in DiscoveredService
                    service.version.as_deref(),
                    None, // reason not available in DiscoveredService
                    service.banner.as_deref(),
                )
                .await
            {
                log::error!("Failed to store port {}: {}", service.port, e);
            }
        }

        // Note: Vulnerability information would be stored from scan result vulnerabilities
        // DiscoveredHost doesn't have vulnerabilities field, they're in scan_result.vulnerabilities
        for vuln_data in &scan_result.vulnerabilities {
            // Process vulnerability data from scan result
            if let Ok(vuln_name) = vuln_data
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or("No name")
            {
                let severity_str = vuln_data
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("info");

                let description = vuln_data
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let cve = vuln_data.get("cve_id").and_then(|v| v.as_str());

                let cvss_score = vuln_data
                    .get("cvss_score")
                    .and_then(|v| v.as_f64())
                    .map(|f| f as f32);

                if let Err(e) = self
                    .database
                    .add_vulnerability(
                        &host.id,
                        None, // port_id - could associate with specific port if available
                        vuln_name,
                        severity_str,
                        Some(description),
                        cve,
                        cvss_score,
                    )
                    .await
                {
                    log::error!("Failed to store vulnerability {}: {}", vuln_name, e);
                }
            }
        }

        Ok(host)
    }

    /// Store scan results in database using StoredPort and StoredVulnerability
    async fn store_scan_results(
        database: &DatabaseOperations,
        scan_result: &NmapScanResult,
    ) -> Result<()> {
        // Store host information
        let host_id = uuid::Uuid::new_v4().to_string();
        let host_ip = scan_result.target_id.clone();

        let _stored_host = database.upsert_host(&host_ip, None).await?;

        // Store ports using simplified API
        for port in &scan_result.open_ports {
            if let Err(e) = database
                .add_port(
                    &host_id,
                    port.number,
                    "tcp", // Default to TCP for now
                    Some("open"),
                    port.service.as_deref(),
                    None, // product not available in ScanPort
                    port.version.as_deref(),
                    None, // reason not available in ScanPort
                    port.banner.as_deref(),
                )
                .await
            {
                log::error!("Failed to store port {}: {}", port.number, e);
            }
        }

        // Store vulnerabilities using simplified API (if any found)
        for vuln in &scan_result.vulnerabilities {
            if let Err(e) = database
                .add_vulnerability(
                    &host_id,
                    None, // port_id not available in this context
                    &vuln.name,
                    &vuln.severity.to_string(),
                    Some(&vuln.description),
                    vuln.cve_id.as_deref(),
                    vuln.cvss_score,
                )
                .await
            {
                log::error!("Failed to store vulnerability {}: {}", vuln.name, e);
            }
        }

        Ok(())
    }

    async fn handle_scan_result(
        scan_id: Uuid,
        result: Result<NmapScanResult>,
        database: Arc<DatabaseOperations>,
        results_tx: mpsc::Sender<ScanEvent>,
    ) {
        match result {
            Ok(scan_result) => {
                log::info!("Scan {} completed successfully", scan_id);

                // Process and store scan results in database
                if let Err(e) = Self::store_scan_results(&database, &scan_result).await {
                    log::error!("Failed to store scan results for {}: {}", scan_id, e);
                }

                // Send success event
                let _ = results_tx
                    .send(ScanEvent {
                        scan_id: scan_id.to_string(),
                        event_type: EventType::ScanCompleted,
                        timestamp: Utc::now(),
                        data: serde_json::json!({
                            "scan_id": scan_id.to_string(),
                            "status": "completed",
                            "hosts_found": 1,
                            "ports_found": scan_result.open_ports.len(),
                        }),
                    })
                    .await;
            }
            Err(e) => {
                log::error!("Scan {} failed: {}", scan_id, e);
                // Send failure event
                let _ = results_tx
                    .send(ScanEvent {
                        scan_id: scan_id.to_string(),
                        event_type: EventType::ScanFailed,
                        timestamp: Utc::now(),
                        data: serde_json::json!({
                            "scan_id": scan_id.to_string(),
                            "status": "failed",
                            "error": e.to_string(),
                        }),
                    })
                    .await;
            }
        }
    }

    async fn handle_scan_completion(
        &self,
        scan_id: uuid::Uuid,
        mut scan_result: ScanResult,
    ) -> Result<()> {
        // Process and store results
        let host = self.process_scan_result(&mut scan_result).await?;
        self.database
            .update_host_status(&host.id, HostStatus::Up)
            .await?;

        // Emit completion event
        let completion_event = crate::scanning::events::ScanEvent {
            scan_id: scan_id.to_string(),
            event_type: crate::scanning::events::EventType::ScanCompleted,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "results": {
                    "hosts_discovered": 1,
                    "ports_found": scan_result.services.len(),
                    "vulnerabilities": 0, // Vulnerabilities would be in DiscoveredHost
                    "os_detected": false, // OS detection would be in DiscoveredHost
                    "scan_duration": scan_result.duration_seconds.unwrap_or(0)
                }
            }),
        };

        let _ = self.results_tx.send(completion_event).await;

        Ok(())
    }
}
