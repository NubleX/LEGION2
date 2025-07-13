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

use crate::scanning::nmap::NmapScanner;
use crate::scanning::models::{ScanStatus, ScanTarget, ScanType, ScanProgress, ScanStatistics};
use crate::scanning::events::{ScanEvent, EventType};
use crate::database::DatabaseOperations;
use crate::database::models::HostStatus;
#[allow(unused_imports)]
use crate::shared::{StoredPort, StoredVulnerability}; // These have to be used. IDE is blind.
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

pub struct ScanCoordinator {
    database: Arc<DatabaseOperations>,
    active_scans: Arc<RwLock<HashMap<uuid::Uuid, ScanHandle>>>,
    results_tx: mpsc::Sender<ScanEvent>,
    nmap_scanner: Arc<NmapScanner>,
}

struct ScanHandle {
    cancel_tx: mpsc::Sender<()>,
    status: Arc<Mutex<ScanStatus>>,
}

impl ScanCoordinator {
    pub fn new(database: Arc<DatabaseOperations>, results_tx: mpsc::Sender<ScanEvent>) -> Self {
        Self {
            database,
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            results_tx,
            nmap_scanner: Arc::new(NmapScanner::new()),
        }
    }

    pub async fn start_scan(&self, target: ScanTarget) -> Result<uuid::Uuid> {
        let scan_id = uuid::Uuid::new_v4();
        log::info!("ScanCoordinator::start_scan called for target: {:?} with scan_id: {}", target, scan_id);
        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);
        
        // Create scan record in database
        let host = self.database.upsert_host(&target.ip.to_string(), target.hostname.as_deref()).await?;
        let host_id = host.id.clone();

        // Store scan handle
        {
            let mut scans = self.active_scans.write().await;
            scans.insert(scan_id, ScanHandle {
                cancel_tx,
                status: Arc::new(Mutex::new(ScanStatus::Running)),
            });
        }

        // Clone for async task
        let scanner = self.nmap_scanner.clone();
        let active_scans = self.active_scans.clone();
        let coordinator = Arc::new(Self {
            database: self.database.clone(),
            active_scans: self.active_scans.clone(),
            results_tx: self.results_tx.clone(),
            nmap_scanner: self.nmap_scanner.clone(),
        });

        // Create progress channel
        let (progress_tx, mut progress_rx) = mpsc::channel(100);

        // Spawn scan task
        tokio::spawn(async move {
            let result: Result<(), anyhow::Error> = async {
                // Run the scan
                let result = tokio::select! {
                    _ = cancel_rx.recv() => {
                        log::info!("Scan {} cancelled", scan_id);
                        Err(anyhow::anyhow!("Scan cancelled"))
                    }
                    scan_result = scanner.scan_target(&target, progress_tx, Some(coordinator.results_tx.clone())) => {
                        scan_result
                    }
                };

                // Process result
                match result {
                    Ok(scan_result) => {
                        if let Err(e) = coordinator.handle_scan_completion(scan_id, scan_result).await {
                            log::error!("Failed to handle scan completion: {}", e);
                        }
                    }
                    Err(e) => {
                        log::error!("Scan failed: {}", e);
                        if let Err(db_err) = coordinator.database.update_host_status(&host_id, HostStatus::Unknown, Some(0.0)).await {
                            log::error!("Failed to update host status after scan failure: {}", db_err);
                        }
                        let failed_scan_event = ScanEvent {
                            scan_id: scan_id.to_string(),
                            event_type: EventType::ScanError,
                            timestamp: chrono::Utc::now(),
                            data: serde_json::json!({ "error": e.to_string() }),
                        };
                        let _ = coordinator.results_tx.send(failed_scan_event).await;
                    }
                }

                // Remove from active scans
                let mut scans = active_scans.write().await;
                scans.remove(&scan_id);
                Ok(())
            }.await;

            if let Err(e) = result {
                log::error!("Scan task failed: {}", e);
                
                if let Ok(host) = coordinator.database.get_host_by_ip(&target.ip.to_string()).await {
                    let _ = coordinator.database.update_host_status(&host.id, HostStatus::Unknown, None).await;
                }
            }
        });

        // Spawn progress monitor
        let _window_clone = self.results_tx.clone();
        tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                // In a real implementation, emit this to the frontend
                log::debug!("Scan progress: {}%", progress.progress);
            }
        });

        Ok(scan_id)
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

    async fn process_scan_result(&self, scan_result: &mut crate::scanning::models::ScanResult) -> Result<crate::database::models::Host> {
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