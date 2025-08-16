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

use crate::shared::Host;
use crate::database::Db;
use tauri::State;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

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
    db.get_all_hosts().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_host_details(
    host_id: String,
    db: State<'_, Arc<Db>>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let ports = db.get_host_ports(&host_id).await.map_err(|e| e.to_string())?;
    let vulns = db.get_host_vulnerabilities(&host_id).await.map_err(|e| e.to_string())?;
    Ok((ports, vulns))
}

#[tauri::command]
pub async fn delete_host(
    host_id: String,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    db.delete_host(&host_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn batch_import_hosts(
    hosts: Vec<String>,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    for ip in hosts {
        if let Err(e) = db.upsert_host(&ip, None, None).await {
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
    db.update_host_tags(&host_id, &tags).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_host_os_detection(
    host_ip: String,
    os_detection: crate::scanning::models::OSDetection,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    db.update_host_os(
        &host_ip,
        Some(&os_detection.name),
        Some(&os_detection.family),
        Some(os_detection.accuracy),
    ).await.map_err(|e| format!("Failed to update OS detection for {}: {}", host_ip, e))
}

#[tauri::command]
pub async fn get_host_by_ip(db: State<'_, Arc<Db>>, ip: String) -> Result<Host, String> {
    let hosts = db.get_all_hosts().await.map_err(|e| e.to_string())?;
    hosts.into_iter()
        .find(|h| h.ip == ip)
        .ok_or_else(|| "Host not found".to_string())
}

#[tauri::command]
pub async fn get_host_ports_detailed(
    host_ip: String,
    db: State<'_, Arc<Db>>,
) -> Result<Vec<PortInfo>, String> {
    log::info!("Getting ports for host IP: {}", host_ip);
    
    // First get the host ID by IP
    let hosts = db.get_all_hosts().await.map_err(|e| e.to_string())?;
    log::info!("Found {} total hosts in database", hosts.len());
    
    let host = hosts.into_iter().find(|h| h.ip == host_ip)
        .ok_or_else(|| format!("Host not found for IP: {}", host_ip))?;
    
    log::info!("Found host with ID: {} for IP: {}", host.id, host_ip);
    
    let ports = db.get_host_ports_detailed(&host.id).await.map_err(|e| e.to_string())?;
    log::info!("Found {} ports for host ID: {}", ports.len(), host.id);
    
    Ok(ports)
}