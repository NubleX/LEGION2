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
    let target_ip: std::net::IpAddr = options.target_ip.parse().map_err(|e| format!("Invalid IP address: {}", e))?;

    let scan_target = ScanTarget {
        id: Uuid::new_v4().to_string(),
        ip: target_ip,
        hostname: None,
        ports: None,
        scan_type: options.scan_type,
    };

    let scan_id = coordinator.start_scan(scan_target).await.map_err(|e| e.to_string())?;
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
    _coordinator: State<'_, Arc<ScanCoordinator>>,
) -> Result<Vec<ScanProgress>, String> {
    // This function needs to be implemented to return actual progress from the coordinator
    // For now, returning an empty vector
    Ok(Vec::new())
}

#[tauri::command]
pub fn is_scanning(_coordinator: State<'_, Arc<ScanCoordinator>>) -> bool {
    // This function needs to be implemented to check if any scans are active
    // For now, returning false
    false
}