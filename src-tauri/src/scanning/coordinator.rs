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
use std::sync::Arc;
use tokio::sync::mpsc;
use parking_lot::RwLock;
use std::collections::HashMap;
use uuid::Uuid;
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;
use chrono::Utc;

use crate::scanning::{
    masscan::MasscanScanner,
    nmap::NmapScanner,
    models::{ScanTarget, ScanType, ScanProgress, ScanResult},
    events::{ScanEvent, EventType},
};
use crate::database::DatabaseOperations;
use crate::shared::{models::Host, StoredPort, StoredVulnerability, HostStatus};

#[derive(Debug, Clone)]
pub struct ScanHandle {
    pub cancel_tx: mpsc::Sender<()>,
    pub status: Arc<tokio::sync::Mutex<ScanStatus>>,
}

#[derive(Debug, Clone)]
pub enum ScanStatus {
    Running,
    Failed(String),
}

pub struct ScanCoordinator {
    database: Arc<DatabaseOperations>,
    active_scans: Arc<RwLock<HashMap<Uuid, ScanHandle>>>,
    results_tx: mpsc::Sender<ScanEvent>,
    nmap_scanner: Arc<NmapScanner>,
    masscan_scanner: Arc<MasscanScanner>,
}

impl ScanCoordinator {
    pub fn new(database: Arc<DatabaseOperations>, results_tx: mpsc::Sender<ScanEvent>) -> Self {
        Self {
            database,
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            results_tx,
            nmap_scanner: Arc::new(NmapScanner::new()),
            masscan_scanner: Arc::new(MasscanScanner::new()),
        }
    }

    pub async fn start_scan(&self, target: ScanTarget) -> Result<Uuid> {
        let scan_id = Uuid::new_v4();
        log::info!("Starting scan for target: {:?} with ID: {}", target, scan_id);

        let (cancel_tx, cancel_rx) = mpsc::channel(1);
        let (progress_tx, progress_rx) = mpsc::channel(100);

        // Initialize scan
        self.initialize_scan(scan_id, &target, cancel_tx).await?;

        // Spawn scan task
        self.spawn_scan_task(scan_id, target.clone(), cancel_rx, progress_tx).await;

        // Monitor progress
        self.monitor_progress(scan_id, progress_rx);

        Ok(scan_id)
    }

    async fn initialize_scan(&self, scan_id: Uuid, target: &ScanTarget, cancel_tx: mpsc::Sender<()>) -> Result<()> {
        let host = self.database.upsert_host(&target.ip.to_string(), target.hostname.as_deref()).await?;
        
        self.active_scans.write().insert(scan_id, ScanHandle {
            cancel_tx,
            status: Arc::new(tokio::sync::Mutex::new(ScanStatus::Running)),
        });

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
            active_scans.write().remove(&scan_id);
        });
    }

    fn monitor_progress(&self, scan_id: Uuid, mut progress_rx: mpsc::Receiver<ScanProgress>) {
        let results_tx = self.results_tx.clone();
        
        tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                log::debug!("Scan {} progress: {}%", scan_id, progress.progress);
                let _ = results_tx.send(ScanEvent {
                    scan_id: scan_id.to_string(),
                    event_type: EventType::ScanProgress,
                    timestamp: Utc::now(),
                    data: serde_json::json!(progress),
                }).await;
            }
        });
    }

    pub async fn cancel_scan(&self, scan_id: uuid::Uuid) -> Result<()> {
        let scans = self.active_scans.read().await;
        if let Some(handle) = scans.get(&scan_id) {
            let _ = handle.cancel_tx.send(()).await;
            let mut status = handle.status.lock().await;
            *status = ScanStatus::Failed("Cancelled by user".to_string());
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
        let network: IpNet = cidr.parse()
            .map_err(|e| anyhow::anyhow!("Invalid CIDR: {}", e))?;
        
        let exclude_ips: Vec<IpAddr> = exclude.iter()
            .filter_map(|ip| IpAddr::from_str(ip).ok())
            .collect();

        let mut scan_ids = Vec::new();
        let hosts: Vec<IpAddr> = network.hosts()
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
                    let _ = progress_tx.send(ScanProgress {
                        scan_id: scan_id.to_string(),
                        progress: ((index + 1) as f32 / total_hosts as f32) * 100.0,
                        current_target: Some(ip.to_string()),
                        hosts_discovered: (index + 1) as u32,
                        ports_found: 0,
                        vulnerabilities: 0,
                        elapsed_time: 0,
                        estimated_remaining: None,
                        message: Some(format!("Started scan for {}", ip)),
                        start_time: chrono::Utc::now(),
                        current_phase: format!("Scanning {} ({}/{})", ip, index + 1, total_hosts),
                    }).await;
                }
                Err(e) => {
                    log::error!("Failed to start scan for {}: {}", ip, e);
                }
            }
        }

        Ok(scan_ids)
    }

    pub async fn get_active_scans(&self) -> Vec<(uuid::Uuid, ScanStatus)> {
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
            total_scans: active_count,
            active_scans: active_count,
            completed_scans: 0,
            failed_scans: 0,
            total_hosts_discovered: 0,
            total_ports_found: 0,
            total_vulnerabilities: 0,
        }
    }

    async fn process_scan_result(&self, scan_result: &mut crate::scanning::models::ScanResult) -> Result<crate::shared::models::Host> {
        // Extract IP from target_id (assuming target_id is an IP address)
        let target_ip = &scan_result.target_id;
        
        // Store host information using upsert_host
        let host = self.database.upsert_host(target_ip, None).await?;
        
        // Update OS detection if available
        if let Some(os_detection) = &scan_result.os_detection {
            self.database.update_host_os(
                &host.id,
                &os_detection.name,
                &os_detection.family,
                os_detection.accuracy
            ).await?;
        }

        // Store port information
        for port in &scan_result.open_ports {
            let stored_port = crate::shared::StoredPort {
                id: uuid::Uuid::new_v4().to_string(),
                host_id: host.id.clone(),
                number: port.number as i32,
                protocol: port.protocol.clone(),
                state: port.state.clone(),
                service: port.service.clone(),
                version: port.version.clone(),
                banner: port.banner.clone(),
                confidence: port.confidence,
                cpe: port.cpe.clone(),
                discovered_at: chrono::Utc::now(),
                last_seen: chrono::Utc::now(),
            };
            
            if let Err(e) = self.database.add_port(&stored_port).await {
                log::error!("Failed to store port {}: {}", port.number, e);
            }
        }

        // Store vulnerability information
        for vuln in &scan_result.vulnerabilities {
            let stored_vuln = crate::shared::StoredVulnerability {
                id: uuid::Uuid::new_v4().to_string(),
                host_id: host.id.clone(),
                port_id: None, // Associate with specific port if available
                name: vuln.name.clone(),
                severity: vuln.severity.clone(),
                description: vuln.description.clone(),
                cvss_score: vuln.cvss_score,
                cvss_vector: vuln.cvss_vector.clone(),
                cve_id: vuln.cve_id.clone(),
                reference_links: vuln.reference_links.clone(),
                exploitable: vuln.exploitable,
                discovered_at: vuln.discovered_at,
                verified: vuln.verified,
                false_positive: vuln.false_positive,
            };
            
            if let Err(e) = self.database.add_vulnerability(&stored_vuln).await {
                log::error!("Failed to store vulnerability {}: {}", vuln.name, e);
            }
        }

        Ok(host)
    }

    async fn handle_scan_completion(&self, scan_id: uuid::Uuid, mut scan_result: crate::scanning::models::ScanResult) -> Result<()> {
        // Process and store results
        let host = self.process_scan_result(&mut scan_result).await?;
        self.database.update_host_status(&host.id, HostStatus::Up, Some(100.0)).await?;
        
        // Emit completion event
        let completion_event = crate::scanning::events::ScanEvent {
            scan_id: scan_id.to_string(),
            event_type: crate::scanning::events::EventType::ScanCompleted,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "results": {
                    "hosts_discovered": 1,
                    "ports_found": scan_result.open_ports.len(),
                    "vulnerabilities": scan_result.vulnerabilities.len(),
                    "os_detected": scan_result.os_detection.is_some(),
                    "scan_duration": scan_result.duration
                }
            }),
        };
        
        let _ = self.results_tx.send(completion_event).await;
        
        Ok(())
    }
}