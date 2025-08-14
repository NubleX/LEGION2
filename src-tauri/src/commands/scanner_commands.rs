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

use crate::scanning::coordinator::{ScanCoordinator, ScanRequest};

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

