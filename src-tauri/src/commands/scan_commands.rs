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

use tauri::{State, AppHandle};
use uuid::Uuid;
use std::str::FromStr;
use std::sync::Arc;
use crate::scanning::coordinator::ScanCoordinator;
use crate::scanning::models::{ScanProgress, ScanTarget, ScanOptions};
use anyhow::Result;

#[tauri::command]
pub async fn start_network_scan(
    _app: AppHandle,
    options: ScanOptions,
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<String, String> {
    let target_ip: std::net::IpAddr = options.target_ip.parse()
        .map_err(|e| format!("Invalid IP address: {}", e))?;

    let scan_target = ScanTarget {
        id: Uuid::new_v4().to_string(),
        ip: target_ip,
        hostname: None,
        ports: None,
        scan_type: options.scan_type,
    };

    let scan_id = coordinator.start_scan(scan_target).await
        .map_err(|e| e.to_string())?;
    Ok(scan_id.to_string())
}

#[tauri::command]
pub async fn cancel_network_scan(
    scan_id: String,
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<(), String> {
    let uuid = Uuid::from_str(&scan_id).map_err(|e| e.to_string())?;
    coordinator.cancel_scan(uuid).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scan_progress(
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<Vec<ScanProgress>, String> {
    // Get actual scan progress from coordinator
    let active_scans = coordinator.get_active_scans().await;
    let mut progress_list = Vec::new();
    
    for (scan_id, status) in active_scans {
        // Convert scan status to progress
        let progress = match status {
            crate::scanning::models::ScanStatus::Running => {
                // Get actual progress from scan handle if available
                // For now, we'll use a basic progress calculation
                ScanProgress {
                    scan_id: scan_id.to_string(),
                    progress: 50.0, // This should come from actual scan progress
                    current_target: Some("Scanning...".to_string()),
                    hosts_discovered: 0, // Get from actual scan results
                    ports_found: 0,
                    vulnerabilities: 0,
                    elapsed_time: 0, // Calculate from scan start time
                    estimated_remaining: None,
                    message: Some("Scan in progress".to_string()),
                    start_time: chrono::Utc::now(), // Get actual start time
                    current_phase: "Discovery".to_string(),
                }
            }
            crate::scanning::models::ScanStatus::Queued => {
                ScanProgress {
                    scan_id: scan_id.to_string(),
                    progress: 0.0,
                    current_target: None,
                    hosts_discovered: 0,
                    ports_found: 0,
                    vulnerabilities: 0,
                    elapsed_time: 0,
                    estimated_remaining: None,
                    message: Some("Queued".to_string()),
                    start_time: chrono::Utc::now(),
                    current_phase: "Queued".to_string(),
                }
            }
            crate::scanning::models::ScanStatus::Completed => {
                ScanProgress {
                    scan_id: scan_id.to_string(),
                    progress: 100.0,
                    current_target: None,
                    hosts_discovered: 0, // Get from scan results
                    ports_found: 0,
                    vulnerabilities: 0,
                    elapsed_time: 0,
                    estimated_remaining: Some(0),
                    message: Some("Completed".to_string()),
                    start_time: chrono::Utc::now(),
                    current_phase: "Completed".to_string(),
                }
            }
            crate::scanning::models::ScanStatus::Failed(error) => {
                ScanProgress {
                    scan_id: scan_id.to_string(),
                    progress: 0.0,
                    current_target: None,
                    hosts_discovered: 0,
                    ports_found: 0,
                    vulnerabilities: 0,
                    elapsed_time: 0,
                    estimated_remaining: None,
                    message: Some(format!("Failed: {}", error)),
                    start_time: chrono::Utc::now(),
                    current_phase: "Failed".to_string(),
                }
            }
            crate::scanning::models::ScanStatus::Cancelled => {
                ScanProgress {
                    scan_id: scan_id.to_string(),
                    progress: 0.0,
                    current_target: None,
                    hosts_discovered: 0,
                    ports_found: 0,
                    vulnerabilities: 0,
                    elapsed_time: 0,
                    estimated_remaining: None,
                    message: Some("Cancelled".to_string()),
                    start_time: chrono::Utc::now(),
                    current_phase: "Cancelled".to_string(),
                }
            }
        };
        progress_list.push(progress);
    }
    
    Ok(progress_list)
}

#[tauri::command]
pub async fn is_scanning(
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<bool, String> {
    // Check if there are any active scans
    let active_scans = coordinator.get_active_scans().await;
    let has_active_scans = active_scans.iter().any(|(_, status)| {
        matches!(status, crate::scanning::models::ScanStatus::Running | 
                        crate::scanning::models::ScanStatus::Queued)
    });
    
    Ok(has_active_scans)
}

#[tauri::command]
pub async fn get_scan_statistics(
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<crate::scanning::models::ScanStatistics, String> {
    // Get real statistics from coordinator
    let stats = coordinator.get_scan_statistics().await;
    Ok(stats)
}

#[tauri::command]
pub async fn scan_network_range(
    cidr: String,
    exclude: Vec<String>,
    scan_type: String,
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<Vec<String>, String> {
    // Parse scan type
    let scan_type_enum = match scan_type.as_str() {
        "quick" => crate::scanning::models::ScanType::Quick,
        "comprehensive" => crate::scanning::models::ScanType::Comprehensive,
        "stealth" => crate::scanning::models::ScanType::Stealth,
        "discovery" => crate::scanning::models::ScanType::Discovery,
        "port_scan" => crate::scanning::models::ScanType::PortScan,
        "service_detection" => crate::scanning::models::ScanType::ServiceDetection,
        "vulnerability" => crate::scanning::models::ScanType::Vulnerability,
        _ => return Err("Invalid scan type".to_string()),
    };

    // Create progress channel (this should be handled properly in coordinator)
    let (progress_tx, _progress_rx) = tokio::sync::mpsc::channel(100);
    
    // Start network range scan
    let scan_ids = coordinator
        .scan_network_range(&cidr, &exclude, scan_type_enum, progress_tx)
        .await
        .map_err(|e| e.to_string())?;
    
    let scan_id_strings: Vec<String> = scan_ids.iter().map(|id| id.to_string()).collect();
    Ok(scan_id_strings)
}