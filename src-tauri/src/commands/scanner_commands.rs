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

use crate::core::{engine::Engine, registry::Registry};
use crate::database::Db;
use crate::plan::{Plan, ScanType};
use serde::Deserialize;
use std::sync::Arc;
use tauri::{AppHandle, Runtime, State};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub scan_type: ScanType,
    pub options: Option<ScanOptions>,
}

#[derive(Debug, Deserialize)]
pub struct ScanOptions {
    pub ports: Option<String>,
    pub rate: Option<u64>,
    pub extra_args: Option<Vec<String>>,
}

#[tauri::command]
pub async fn start_scan<R: Runtime>(
    app: AppHandle<R>,
    state_db: State<'_, Arc<Db>>,
    request: ScanRequest,
) -> Result<String, String> {
    let scan_id = Uuid::new_v4();

    let ports = request
        .options
        .as_ref()
        .and_then(|o| o.ports.clone())
        .unwrap_or_else(|| "1-1000".to_string());

    let plan = match request.scan_type {
        ScanType::Discovery => {
            let rate = request.options.as_ref().and_then(|o| o.rate);
            Plan::masscan(scan_id, request.target.clone(), ports, rate)
        }
        _ => {
            let extra = request
                .options
                .as_ref()
                .and_then(|o| o.extra_args.clone())
                .unwrap_or_default();
            Plan::nmap(scan_id, request.target.clone(), ports, extra)
        }
    };

    let registry = Registry::new(state_db.inner().clone(), app);
    let engine = Engine { registry };

    tokio::spawn(async move {
        if let Err(e) = engine.execute(plan).await {
            log::error!("Engine execution failed: {}", e);
        }
    });

    Ok(scan_id.to_string())
}

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
