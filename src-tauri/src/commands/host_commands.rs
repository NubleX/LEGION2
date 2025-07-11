use crate::database::{DatabaseOperations, Host};
use crate::shared::{StoredPort, StoredVulnerability};
use tauri::State;
use std::sync::Arc;
use anyhow::Result;

#[tauri::command]
pub async fn get_all_hosts(
    db: State<'_, Arc<DatabaseOperations>>,
    status_filter: Option<String>,
) -> Result<Vec<Host>, String> {
    let status = status_filter.and_then(|s| s.parse().ok());
    db.get_hosts(status).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_host_details(
    host_id: String,
    db: State<'_, Arc<DatabaseOperations>>,
) -> Result<(Vec<StoredPort>, Vec<StoredVulnerability>), String> {
    let ports = db.get_host_ports(&host_id).await.map_err(|e| e.to_string())?;
    let vulnerabilities = db.get_host_vulnerabilities(&host_id).await.map_err(|e| e.to_string())?;
    Ok((ports, vulnerabilities))
}

#[tauri::command]
pub async fn delete_host(
    host_id: String,
    db: State<'_, Arc<DatabaseOperations>>,
) -> Result<(), String> {
    db.delete_host(&host_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn batch_import_hosts(
    hosts: Vec<String>,
    db: State<'_, Arc<DatabaseOperations>>,
) -> Result<(), String> {
    for ip in hosts {
        if let Err(e) = db.upsert_host(&ip, None).await {
            return Err(format!("Failed to import host {}: {}", ip, e));
        }
    }
    Ok(())
}