use crate::scanning::*;
use crate::database::{operations::*, models::*};
use crate::utils::InputValidator;
use crate::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::mpsc;
use anyhow::Result as AnyhowResult;

#[tauri::command]
pub async fn start_scan(
    state: State<'_, AppState>,
    target_ip: String,
    scan_type: String,
    window: tauri::Window,
) -> Result<String, String> {
    let ip = InputValidator::validate_ip(&target_ip)
        .map_err(|e| e.to_string())?;
    
    let scan_type_enum = match scan_type.as_str() {
        "quick" => ScanType::Quick,
        "comprehensive" => ScanType::Comprehensive,
        "stealth" => ScanType::Stealth,
        _ => ScanType::Quick,
    };

    let target = ScanTarget {
        id: uuid::Uuid::new_v4(),
        ip,
        hostname: None,
        ports: vec![],
        scan_type: scan_type_enum,
    };

    let (progress_tx, mut progress_rx) = mpsc::channel(100);
    
    // Forward progress updates to frontend
    let window_clone = window.clone();
    let target_ip_clone = target_ip.clone();
    tokio::spawn(async move {
        while let Some(progress) = progress_rx.recv().await {
            let _ = window_clone.emit("scan-progress", &ScanProgressEvent {
                target: target_ip_clone.clone(),
                progress,
            });
        }
    });

    let scan_id = state.scan_coordinator
        .start_scan(target, progress_tx)
        .await
        .map_err(|e| e.to_string())?;

    Ok(scan_id.to_string())
}

#[tauri::command]
pub async fn cancel_scan(
    state: State<'_, AppState>,
    scan_id: String,
) -> Result<(), String> {
    let uuid = uuid::Uuid::parse_str(&scan_id)
        .map_err(|e| format!("Invalid UUID: {}", e))?;
    
    state.scan_coordinator
        .cancel_scan(uuid)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scan_results(
    state: State<'_, AppState>,
) -> Result<Vec<ScanResult>, String> {
    let results = state.scan_results.read().await;
    Ok(results.clone())
}

#[tauri::command]
pub async fn get_active_scans(
    state: State<'_, AppState>,
) -> Result<Vec<ActiveScanInfo>, String> {
    let scans = state.scan_coordinator.get_active_scans().await;
    Ok(scans.into_iter()
        .map(|(id, status)| ActiveScanInfo {
            id: id.to_string(),
            status,
        })
        .collect())
}

#[tauri::command]
pub async fn scan_network_range(
    state: State<'_, AppState>,
    range: NetworkRangeRequest,
    window: tauri::Window,
) -> Result<Vec<String>, String> {
    InputValidator::validate_cidr(&range.cidr)
        .map_err(|e| e.to_string())?;
    
    InputValidator::validate_scan_type(&range.scan_type)
        .map_err(|e| e.to_string())?;

    let scan_type_enum = match range.scan_type.as_str() {
        "quick" => ScanType::Quick,
        "comprehensive" => ScanType::Comprehensive,
        "stealth" => ScanType::Stealth,
        _ => ScanType::Quick,
    };

    let (progress_tx, mut progress_rx) = mpsc::channel(100);
    
    // Forward network scan progress
    let window_clone = window.clone();
    tokio::spawn(async move {
        while let Some(progress) = progress_rx.recv().await {
            let _ = window_clone.emit("network-scan-progress", &progress);
        }
    });

    let scan_ids = state.scan_coordinator
        .scan_network_range(&range.cidr, &range.exclude, scan_type_enum, progress_tx)
        .await
        .map_err(|e| e.to_string())?;
    
    Ok(scan_ids.into_iter().map(|id| id.to_string()).collect())
}

#[tauri::command]
pub async fn get_scan_statistics(
    state: State<'_, AppState>,
) -> Result<ScanStatistics, String> {
    Ok(state.scan_coordinator.get_scan_statistics().await)
}

// Database commands
#[tauri::command]
pub async fn get_hosts(
    state: State<'_, AppState>,
) -> Result<Vec<Host>, String> {
    HostOperations::list_all(state.database.pool())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_host_details(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<HostDetails, String> {
    let (host, ports) = HostOperations::get_with_ports(state.database.pool(), &host_id)
        .await
        .map_err(|e| e.to_string())?;
    
    let vulnerabilities = VulnerabilityOperations::find_by_host(state.database.pool(), &host_id)
        .await
        .map_err(|e| e.to_string())?;

    Ok(HostDetails {
        host,
        ports,
        vulnerabilities,
    })
}

#[tauri::command]
pub async fn get_vulnerabilities(
    state: State<'_, AppState>,
    severity_filter: Option<String>,
) -> Result<Vec<Vulnerability>, String> {
    match severity_filter {
        Some(_) => VulnerabilityOperations::find_high_severity(state.database.pool())
            .await
            .map_err(|e| e.to_string()),
        None => {
            // Get all vulnerabilities - you might want to add this method to VulnerabilityOperations
            sqlx::query_as!(
                Vulnerability,
                "SELECT * FROM vulnerabilities ORDER BY discovered_at DESC"
            )
            .fetch_all(state.database.pool())
            .await
            .map_err(|e| e.to_string())
        }
    }
}

#[tauri::command]
pub async fn create_project(
    state: State<'_, AppState>,
    name: String,
    description: Option<String>,
) -> Result<Project, String> {
    ProjectOperations::create(state.database.pool(), &name, description.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_projects(
    state: State<'_, AppState>,
) -> Result<Vec<Project>, String> {
    ProjectOperations::list_all(state.database.pool())
        .await
        .map_err(|e| e.to_string())
}

// Request/Response types
#[derive(Serialize, Deserialize)]
pub struct NetworkRangeRequest {
    pub cidr: String,
    pub exclude: Vec<String>,
    pub scan_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct ActiveScanInfo {
    pub id: String,
    pub status: ScanStatus,
}

#[derive(Serialize, Deserialize)]
pub struct ScanProgressEvent {
    pub target: String,
    pub progress: ScanProgress,
}

#[derive(Serialize, Deserialize)]
pub struct HostDetails {
    pub host: Host,
    pub ports: Vec<Port>,
    pub vulnerabilities: Vec<Vulnerability>,
}