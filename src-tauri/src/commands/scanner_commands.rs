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

use std::sync::Arc;

use tauri::{AppHandle, State};

use crate::database::Db;
use crate::plan::ScanType;
use crate::scanning::coordinator::{ScanCoordinator, ScanRequest, ScanOptions};

/// Start a scan using the ScanCoordinator
#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    coordinator: State<'_, Arc<ScanCoordinator>>,
    request: ScanRequest,
) -> Result<String, String> {
    coordinator.start_scan(app, request).await
}

/// Cancel a running scan
#[tauri::command]
pub async fn cancel_scan(
    coordinator: State<'_, Arc<ScanCoordinator>>,
    scan_id: String,
) -> Result<(), String> {
    coordinator.cancel_scan(scan_id).await
}

/// Get list of active scans
#[tauri::command]
pub async fn get_active_scans(
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<Vec<String>, String> {
    coordinator.get_active_scans().await
}

/// Retrieve progress information for a scan
#[tauri::command]
pub async fn get_scan_progress(
    coordinator: State<'_, Arc<ScanCoordinator>>,
    scan_id: String,
) -> Result<String, String> {
    coordinator.get_scan_progress(scan_id).await
}

/// Retrieve aggregated scan statistics
#[tauri::command]
pub async fn get_scan_statistics(
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<String, String> {
    coordinator.get_scan_statistics().await
}

/// Report availability of scanning tools
#[tauri::command]
pub async fn get_scanner_status() -> Result<String, String> {
    let nmap_available = crate::utils::os::is_nmap_available().await;
    let masscan_available = crate::utils::os::is_masscan_available().await;

    let status = serde_json::json!({
        "nmap_available": nmap_available,
        "masscan_available": masscan_available,
        "ready": nmap_available || masscan_available
    });

    Ok(status.to_string())
}

/// Start a coordinated scan using the coordinator with ScanOptions
#[tauri::command]
pub async fn start_coordinated_scan(
    target: String,
    scan_type: String,
    ports: Option<String>,
    rate: Option<u32>,
    extra_args: Option<Vec<String>>,
    use_masscan: Option<bool>,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<String, String> {
    log::info!("Starting coordinated scan for target: {}", target);
    
    // Parse scan type
    let scan_type = match scan_type.as_str() {
        "Discovery" => ScanType::Discovery,
        "PortScan" => ScanType::PortScan,
        "ServiceDetection" => ScanType::ServiceDetection,
        "Vulnerability" => ScanType::Vulnerability,
        "Comprehensive" => ScanType::Comprehensive,
        "Quick" => ScanType::Quick,
        "Stealth" => ScanType::Stealth,
        _ => ScanType::Quick,
    };

    let options = ScanOptions {
        ports,
        rate,
        extra_args,
        use_masscan,
    };

    let request = ScanRequest {
        target,
        scan_type,
        options: Some(options),
    };

    let coordinator = ScanCoordinator::new(state_db.inner().clone());
    coordinator.start_scan(app, request).await
}

/// Start a masscan-specific scan using coordinator
#[tauri::command]
pub async fn start_masscan_scan(
    target: String,
    ports: Option<String>,
    rate: Option<u32>,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<String, String> {
    log::info!("Starting masscan scan for target: {}", target);
    
    let options = ScanOptions {
        ports,
        rate,
        extra_args: None,
        use_masscan: Some(true),
    };

    let request = ScanRequest {
        target,
        scan_type: ScanType::PortScan,
        options: Some(options),
    };

    let coordinator = ScanCoordinator::new(state_db.inner().clone());
    coordinator.start_scan(app, request).await
}

/// Start an nmap-specific scan using coordinator
#[tauri::command]
pub async fn start_nmap_scan(
    target: String,
    scan_type: String,
    ports: Option<String>,
    extra_args: Option<Vec<String>>,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<String, String> {
    log::info!("Starting nmap scan for target: {}", target);
    
    // Parse scan type
    let scan_type = match scan_type.as_str() {
        "Discovery" => ScanType::Discovery,
        "PortScan" => ScanType::PortScan,
        "ServiceDetection" => ScanType::ServiceDetection,
        "Vulnerability" => ScanType::Vulnerability,
        "Comprehensive" => ScanType::Comprehensive,
        "Quick" => ScanType::Quick,
        "Stealth" => ScanType::Stealth,
        _ => ScanType::Quick,
    };

    let options = ScanOptions {
        ports,
        rate: None,
        extra_args,
        use_masscan: Some(false),
    };

    let request = ScanRequest {
        target,
        scan_type,
        options: Some(options),
    };

    let coordinator = ScanCoordinator::new(state_db.inner().clone());
    coordinator.start_scan(app, request).await
}
