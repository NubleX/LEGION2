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

#[tauri::command]
pub async fn update_host_os_detection(
    host_id: String,
    os_detection: crate::scanning::models::OSDetection,
    database: State<'_, Arc<DatabaseOperations>>,
) -> Result<(), String> {
    database.update_host_os(
        &host_id, 
        &os_detection.name, 
        &os_detection.family, 
        os_detection.accuracy
    ).await
    .map_err(|e| format!("Failed to update host OS detection: {}", e))?;
    
    Ok(())
}

#[tauri::command]
pub async fn get_host_by_ip(
    ip: String,
    database: State<'_, Arc<DatabaseOperations>>,
) -> Result<crate::database::Host, String> {
    let host = database.get_host_by_ip(&ip).await
        .map_err(|e| format!("Failed to get host: {}", e))?;
    
    Ok(host)
}