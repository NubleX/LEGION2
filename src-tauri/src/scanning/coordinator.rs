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

use crate::commands::scanner_commands::ScanTarget;
use crate::database::Db;
use crate::scanning::{
    events::{EventType, ScanEvent},
    masscan::MasscanScanner,
    models::{ScanProgress, ScanResult, ScanStatistics, ScanType},
    nmap::{NmapScanner, ScanResult as NmapScanResult},
};

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
    database: Arc<Db>,
    active_scans: Arc<RwLock<HashMap<Uuid, ScanHandle>>>,
    results_tx: mpsc::Sender<ScanEvent>,
    nmap_scanner: Arc<NmapScanner>,
    masscan_scanner: Arc<MasscanScanner>,
}

impl ScanCoordinator {
    pub fn borrow(database: Arc<Db>, results_tx: mpsc::Sender<ScanEvent>) -> Self {
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

    pub async fn start_scan(&self, target: ScanTarget, use_masscan: bool) -> Result<Uuid> {
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
        self
            .spawn_scan_task(scan_id, target.clone(), cancel_rx, progress_tx, use_masscan)
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
        use_masscan: bool,
    ) {
        let nmap_scanner = self.nmap_scanner.clone();
        let masscan_scanner = self.masscan_scanner.clone();
        let active_scans = self.active_scans.clone();
        let results_tx = self.results_tx.clone();
        let database = self.database.clone();

        tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancel_rx.recv() => {
                    log::info!("Scan {} cancelled", scan_id);
                    Err(anyhow::anyhow!("Scan cancelled"))
                }
                scan_result = async {
                    let mut target = target;
                    if use_masscan {
                        let progress_clone = progress_tx.clone();
                        match masscan_scanner
                            .scan_target(&target, progress_clone, results_tx.clone())
                            .await
                        {
                            Ok(ports) => {
                                if !ports.is_empty() {
                                    target.ports = Some(ports);
                                }
                            }
                            Err(e) => {
                                log::error!("Masscan failed for {}: {}", target.ip, e);
                            }
                        }
                    }
                    nmap_scanner
                        .scan_target(&target, progress_tx, Some(results_tx.clone()))
                        .await
                } => {
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

            match self.start_scan(target, false).await {
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

    /// Store scan results in the simple synchronous Db
    fn store_scan_results(database: &Db, scan_result: &NmapScanResult) -> Result<()> {
        let now = Utc::now();
        let host_ip = scan_result.target_id.clone();
        database.upsert_host(&host_ip, now)?;

        for port in &scan_result.open_ports {
            if let Err(e) = database.upsert_service(&host_ip, port.number, "tcp", Some("open"), now)
            {
                log::error!("Failed to store port {}: {}", port.number, e);
            }
        }
        Ok(())
    }

    async fn handle_scan_result(
        scan_id: Uuid,
        result: Result<NmapScanResult>,
        database: Arc<Db>,
        results_tx: mpsc::Sender<ScanEvent>,
    ) {
        match result {
            Ok(scan_result) => {
                log::info!("Scan {} completed successfully", scan_id);

                // Process and store scan results in database
                if let Err(e) = Self::store_scan_results(&database, &scan_result) {
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
}
