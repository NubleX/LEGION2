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

#[tauri::command]
pub async fn get_all_hosts(
    db: State<'_, Arc<Db>>,
    _status_filter: Option<String>,
) -> Result<Vec<Host>, String> {
    db.get_all_hosts().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_host_details(
    _host_id: String,
    _db: State<'_, Arc<Db>>,
) -> Result<(Vec<String>, Vec<String>), String> {
    // TODO: Implement when port/vulnerability schema is added to Db
    Ok((Vec::new(), Vec::new()))
}

#[tauri::command]
pub async fn delete_host(
    _host_id: String,
    _db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    // TODO: Implement host deletion in Db
    Ok(())
}

#[tauri::command]
pub async fn batch_import_hosts(
    hosts: Vec<String>,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    for ip in hosts {
        if let Err(e) = db.upsert_host(&ip, chrono::Utc::now()) {
            return Err(format!("Failed to import host {}: {}", ip, e));
        }
    }
    Ok(())
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
    ).map_err(|e| format!("Failed to update OS detection for {}: {}", host_ip, e))
}

#[tauri::command]
pub async fn get_host_by_ip(_db: State<'_, Arc<Db>>, _ip: String) -> Result<Host, String> {
    // TODO: Implement get_host_by_ip in Db
    Err("Not implemented".to_string())
}