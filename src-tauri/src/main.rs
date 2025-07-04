// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod scanning;
mod commands;
mod database;
mod utils;

use commands::*;
use scanning::*;
use database::Database;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use anyhow::Result;
use tauri::{Manager, Emitter};

#[derive(Clone)]
pub struct AppState {
    pub scan_coordinator: Arc<ScanCoordinator>,
    pub scan_results: Arc<RwLock<Vec<ScanResult>>>,
    pub database: Arc<Database>,
}

async fn initialize_database() -> Result<Arc<Database>> {
    let database = Database::new().await?;
    Ok(Arc::new(database))
}

async fn setup_result_handler(
    results_storage: Arc<RwLock<Vec<ScanResult>>>,
    mut results_rx: mpsc::Receiver<ScanResult>,
    app_handle: tauri::AppHandle,
) {
    while let Some(result) = results_rx.recv().await {
        // Store in memory
        {
            let mut results = results_storage.write().await;
            results.push(result.clone());
        }
        
        // Emit to frontend
        if let Some(window) = app_handle.get_webview_window("main") {
            let _ = window.emit("scan-result", &result);
        }
        
        // Log completion
        println!("Scan completed for {}: {} open ports", 
            result.target_id, result.open_ports.len());
    }
}

fn main() {
    tauri::async_runtime::block_on(async {
        if let Err(e) = run_app().await {
            eprintln!("Application error: {}", e);
            std::process::exit(1);
        }
    });
}

async fn run_app() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Initialize database
    let database = initialize_database().await?;
    
    // Create result channels
    let (results_tx, results_rx) = mpsc::channel(1000);
    
    // Initialize scan coordinator
    let scan_coordinator = Arc::new(ScanCoordinator::new(database.clone(), results_tx));
    let scan_results = Arc::new(RwLock::new(Vec::new()));

    let app_state = AppState {
        scan_coordinator,
        scan_results: scan_results.clone(),
        database,
    };

    tauri::Builder::default()
        .manage(app_state)
        .setup(|app| {
            let app_handle = app.handle().clone();
            
            // Setup result handler
            tauri::async_runtime::spawn(setup_result_handler(
                scan_results,
                results_rx,
                app_handle,
            ));
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_scan,
            cancel_scan,
            get_scan_results,
            get_active_scans,
            scan_network_range,
            get_scan_statistics,
            get_hosts,
            get_host_details,
            get_vulnerabilities,
            create_project,
            list_projects
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");

    Ok(())
}