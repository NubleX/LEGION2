// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::database::Db;
use crate::shared::Host;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub number: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[tauri::command]
pub async fn get_all_hosts(
    db: State<'_, Arc<Db>>,
    _status_filter: Option<String>,
) -> Result<Vec<Host>, String> {
    db.inner().get_all_hosts().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_host_details(
    host_id: String,
    db: State<'_, Arc<Db>>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let ports = db
        .inner()
        .get_host_ports(&host_id)
        .await
        .map_err(|e| e.to_string())?;
    let vulns = db
        .inner()
        .get_host_vulnerabilities(&host_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok((ports, vulns))
}

#[tauri::command]
pub async fn delete_host(host_id: String, db: State<'_, Arc<Db>>) -> Result<(), String> {
    db.inner()
        .delete_host(&host_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn batch_import_hosts(hosts: Vec<String>, db: State<'_, Arc<Db>>) -> Result<(), String> {
    for ip in hosts {
        if let Err(e) = db
            .inner()
            .upsert_host(&ip, None, None, None, None, None, None, None)
            .await
        {
            return Err(format!("Failed to import host {}: {}", ip, e));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn update_host_tags(
    host_id: String,
    tags: Vec<String>,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    db.inner()
        .update_host_tags(&host_id, &tags)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_host_os_detection(
    host_ip: String,
    os_detection: crate::scanning::models::OSDetection,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    db.inner()
        .update_host_os(
            &host_ip,
            Some(&os_detection.name),
            Some(&os_detection.family),
            Some(os_detection.accuracy),
        )
        .await
        .map_err(|e| format!("Failed to update OS detection for {}: {}", host_ip, e))
}

#[tauri::command]
pub async fn get_host_by_ip(db: State<'_, Arc<Db>>, ip: String) -> Result<Host, String> {
    let hosts = db
        .inner()
        .get_all_hosts()
        .await
        .map_err(|e| e.to_string())?;
    hosts
        .into_iter()
        .find(|h| h.ip == ip)
        .ok_or_else(|| "Host not found".to_string())
}

#[tauri::command]
pub async fn get_host_ports_detailed(
    host_ip: String,
    db: State<'_, Arc<Db>>,
) -> Result<Vec<PortInfo>, String> {
    log::info!("Getting ports for host IP: {}", host_ip);

    // Ensure the host exists in the database. If it was just created during a scan,
    // this will insert it so we can still query its ports without errors.
    if let Err(e) = db
        .inner()
        .upsert_host(&host_ip, None, None, None, None, None, None, None)
        .await
    {
        log::warn!("Failed to upsert host {}: {}", host_ip, e);
    }

    // Ports are keyed by host IP, so we can query them directly.
    let ports = db
        .inner()
        .get_host_ports_detailed(&host_ip)
        .await
        .map_err(|e| e.to_string())?;
    log::info!("Found {} ports for host IP: {}", ports.len(), host_ip);

    Ok(ports)
}
