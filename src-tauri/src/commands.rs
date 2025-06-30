use crate::scanning::*;
use crate::database::{operations::*};
use crate::AppState;
use tauri::{State, Window, Emitter};
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::str::FromStr;

// Import database types with aliases to avoid conflicts
use crate::database::models::{
    Host as DbHost, 
    Port as DbPort, 
    Vulnerability as DbVulnerability,
    Project as DbProject
};

// Conversion functions between database and scanning types
impl From<DbVulnerability> for Vulnerability {
    fn from(db_vuln: DbVulnerability) -> Self {
        let severity = match db_vuln.severity.as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Info,
        };

        let references = if let Some(ref_str) = db_vuln.references {
            serde_json::from_str(&ref_str).unwrap_or_default()
        } else {
            Vec::new()
        };

        Vulnerability {
            id: db_vuln.id,
            name: db_vuln.name,
            severity,
            description: db_vuln.description,
            cvss_score: db_vuln.cvss_score,
            references,
        }
    }
}

impl From<DbPort> for Port {
    fn from(db_port: DbPort) -> Self {
        Port {
            number: db_port.number as u16,
            protocol: db_port.protocol,
            state: db_port.state,
            service: db_port.service,
            version: db_port.version,
            banner: db_port.banner,
        }
    }
}

impl From<DbHost> for Host {
    fn from(db_host: DbHost) -> Self {
        Host {
            id: db_host.id,
            ip: db_host.ip,
            hostname: db_host.hostname,
            os: db_host.os_name,
            status: db_host.status,
            discovered_at: db_host.created_at.to_rfc3339(),
        }
    }
}

impl From<DbProject> for Project {
    fn from(db_project: DbProject) -> Self {
        Project {
            id: db_project.id,
            name: db_project.name,
            description: db_project.description,
            created_at: db_project.created_at.to_rfc3339(),
        }
    }
}

// Commands
#[tauri::command]
pub async fn start_scan(
    state: State<'_, AppState>,
    target: ScanTarget,
    window: Window,
) -> Result<String, String> {
    let scan_id = state.scan_coordinator.start_scan(target).await
        .map_err(|e| e.to_string())?;
    
    Ok(scan_id.to_string())
}

#[tauri::command]
pub async fn cancel_scan(
    state: State<'_, AppState>,
    scan_id: String,
) -> Result<(), String> {
    let uuid = Uuid::from_str(&scan_id)
        .map_err(|e| format!("Invalid scan ID: {}", e))?;
    
    state.scan_coordinator.cancel_scan(uuid).await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scan_results(
    state: State<'_, AppState>,
    scan_id: Option<String>,
) -> Result<Vec<ScanResult>, String> {
    let results = state.scan_results.read().await;
    
    if let Some(id) = scan_id {
        let uuid = Uuid::from_str(&id)
            .map_err(|e| format!("Invalid scan ID: {}", e))?;
        Ok(results.iter()
            .filter(|r| r.id == uuid)
            .cloned()
            .collect())
    } else {
        Ok(results.clone())
    }
}

#[tauri::command]
pub async fn get_active_scans(
    state: State<'_, AppState>,
) -> Result<Vec<ActiveScanInfo>, String> {
    let active_scans = state.scan_coordinator.get_active_scans().await;
    
    Ok(active_scans.into_iter().map(|(id, status)| ActiveScanInfo {
        id: id.to_string(),
        status,
    }).collect())
}

#[tauri::command]
pub async fn scan_network_range(
    state: State<'_, AppState>,
    range: NetworkRangeRequest,
    window: Window,
) -> Result<Vec<String>, String> {
    use crate::utils::validation::InputValidator;
    
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

// Database commands with type conversion
#[tauri::command]
pub async fn get_hosts(
    state: State<'_, AppState>,
) -> Result<Vec<Host>, String> {
    let db_hosts = HostOperations::list_all(&state.database)
        .await
        .map_err(|e| e.to_string())?;
    
    Ok(db_hosts.into_iter().map(Host::from).collect())
}

#[tauri::command]
pub async fn get_host_details(
    state: State<'_, AppState>,
    host_id: String,
) -> Result<HostDetails, String> {
    let (db_host, db_ports) = HostOperations::get_with_ports(&state.database, &host_id)
        .await
        .map_err(|e| e.to_string())?;
    
    let db_vulnerabilities = VulnerabilityOperations::find_by_host(&state.database, &host_id)
        .await
        .map_err(|e| e.to_string())?;

    let host = Host::from(db_host);
    let ports = db_ports.into_iter().map(Port::from).collect();
    let vulnerabilities = db_vulnerabilities.into_iter().map(Vulnerability::from).collect();

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
    let db_vulnerabilities = match severity_filter {
        Some(_) => VulnerabilityOperations::find_high_severity(&state.database)
            .await
            .map_err(|e| e.to_string())?,
        None => VulnerabilityOperations::list_all(&state.database)
            .await
            .map_err(|e| e.to_string())?
    };
    
    Ok(db_vulnerabilities.into_iter().map(Vulnerability::from).collect())
}

#[tauri::command]
pub async fn create_project(
    state: State<'_, AppState>,
    name: String,
    description: Option<String>,
) -> Result<Project, String> {
    let db_project = ProjectOperations::create(&state.database, &name, description.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    
    Ok(Project::from(db_project))
}

#[tauri::command]
pub async fn list_projects(
    state: State<'_, AppState>,
) -> Result<Vec<Project>, String> {
    let db_projects = ProjectOperations::list_all(&state.database)
        .await
        .map_err(|e| e.to_string())?;
    
    Ok(db_projects.into_iter().map(Project::from).collect())
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