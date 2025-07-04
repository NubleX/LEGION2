// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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

use super::*;
use crate::database::{Database, operations::*};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanStatistics {
    pub total_scans: u32,
    pub active_scans: u32,
    pub completed_scans: u32,
    pub failed_scans: u32,
    pub total_hosts_discovered: u32,
    pub total_ports_found: u32,
    pub total_vulnerabilities: u32,
}

pub struct ScanCoordinator {
    database: Arc<Database>,
    active_scans: Arc<RwLock<HashMap<uuid::Uuid, ScanHandle>>>,
    results_tx: mpsc::Sender<ScanResult>,
    nmap_scanner: Arc<NmapScanner>,
}

struct ScanHandle {
    cancel_tx: mpsc::Sender<()>,
    status: Arc<Mutex<ScanStatus>>,
}

impl ScanCoordinator {
    pub fn new(database: Arc<Database>, results_tx: mpsc::Sender<ScanResult>) -> Self {
        Self {
            database,
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            results_tx,
            nmap_scanner: Arc::new(NmapScanner::new()),
        }
    }

    pub async fn start_scan(&self, target: ScanTarget) -> Result<uuid::Uuid> {
        let scan_id = uuid::Uuid::new_v4();
        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);
        
        // Create scan record in database
        let host = HostOperations::upsert(
            &self.database, 
            &target.ip.to_string(), 
            target.hostname.as_deref()
        ).await?;

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
        let results_tx = self.results_tx.clone();
        let active_scans = self.active_scans.clone();
        let db = self.database.clone();
        let host_id = host.id.clone();

        // Create progress channel
        let (progress_tx, mut progress_rx) = mpsc::channel(100);

        // Spawn scan task
        tokio::spawn(async move {
            // Run the scan
            let result = tokio::select! {
                _ = cancel_rx.recv() => {
                    log::info!("Scan {} cancelled", scan_id);
                    Err(anyhow::anyhow!("Scan cancelled"))
                }
                scan_result = scanner.scan_target(&target, progress_tx) => {
                    scan_result
                }
            };

            // Process result
            match result {
                Ok(mut scan_result) => {
                    // Store results in database
                    for port in &scan_result.open_ports {
                        if let Err(e) = PortOperations::create(
                            &db,
                            &host_id,
                            port.number as i32,
                            &port.protocol,
                            &port.state,
                            port.service.as_deref(),
                            port.version.as_deref(),
                        ).await {
                            log::error!("Failed to store port: {}", e);
                        }
                    }

                    // Store OS detection if available
                    if let Some(os) = &scan_result.os_detection {
                        if let Err(e) = HostOperations::update_os(
                            &db,
                            &host_id,
                            &os.name,
                            &os.vendor,
                            os.accuracy,
                        ).await {
                            log::error!("Failed to update OS info: {}", e);
                        }
                    }

                    // Update scan status
                    scan_result.status = ScanStatus::Completed;
                    
                    // Send result
                    let _ = results_tx.send(scan_result).await;
                }
                Err(e) => {
                    log::error!("Scan failed: {}", e);
                    let failed_result = ScanResult {
                        id: scan_id,
                        target_id: target.id,
                        timestamp: chrono::Utc::now(),
                        status: ScanStatus::Failed { 
                            error: e.to_string() 
                        },
                        open_ports: Vec::new(),
                        os_detection: None,
                        vulnerabilities: Vec::new(),
                    };
                    let _ = results_tx.send(failed_result).await;
                }
            }

            // Remove from active scans
            let mut scans = active_scans.write().await;
            scans.remove(&scan_id);
        });

        // Spawn progress monitor
        let window_clone = self.results_tx.clone();
        tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                // In a real implementation, you'd emit this to the frontend
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
            *status = ScanStatus::Failed { 
                error: "Cancelled by user".to_string() 
            };
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
                id: uuid::Uuid::new_v4(),
                ip,
                hostname: None,
                ports: Vec::new(),
                scan_type: scan_type.clone(),
            };

            match self.start_scan(target).await {
                Ok(scan_id) => {
                    scan_ids.push(scan_id);
                    
                    // Send progress update
                    let _ = progress_tx.send(ScanProgress {
                        scan_id: scan_id.to_string(),
                        target_id: scan_id.to_string(),
                        progress: ((index + 1) as f32 / total_hosts as f32) * 100.0,
                        current_phase: format!("Scanning {} ({}/{})", ip, index + 1, total_hosts),
                        discovered_hosts: index as i32 + 1,
                        total_ports_scanned: 0,
                        open_ports_found: 0,
                        estimated_time_remaining: None,
                        message: Some(format!("Started scan for {}", ip)),
                        start_time: chrono::Utc::now(),
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
        
        // You could query the database for more detailed stats
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
}