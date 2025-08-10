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

use crate::scanning::coordinator::ScanCoordinator;
use crate::scanning::models::{ScanTarget, ScanType};
use tauri::{State, AppHandle, Runtime};
use std::sync::Arc;
use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub scan_type: ScanType,
    pub options: Option<ScanOptions>,
}

#[derive(Deserialize)]
pub struct ScanOptions {
    pub ports: Option<String>,
    pub rate: Option<u32>,
    pub extra_args: Option<Vec<String>>,
}

#[tauri::command]
pub async fn start_scan<R: Runtime>(
    app: AppHandle<R>,
    coordinator: State<'_, Arc<ScanCoordinator>>,
    request: ScanRequest,
) -> Result<String, String> {
    // Convert the request into a ScanTarget
    let target = ScanTarget::from_string(&request.target)
        .map_err(|e| e.to_string())?;

    // Start the scan using the coordinator
    let scan_id = coordinator.start_scan(target)
        .await
        .map_err(|e| e.to_string())?;

    Ok(scan_id.to_string())
}

#[tauri::command]
pub async fn cancel_scan(
    coordinator: State<'_, Arc<ScanCoordinator>>,
    scan_id: String,
) -> Result<(), String> {
    let uuid = uuid::Uuid::parse_str(&scan_id)
        .map_err(|e| e.to_string())?;
    
    coordinator.cancel_scan(uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_active_scans(
    coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<Vec<String>, String> {
    let scans = coordinator.get_active_scans()
        .await
        .into_iter()
        .map(|(id, _)| id.to_string())
        .collect();
    
    Ok(scans)
}