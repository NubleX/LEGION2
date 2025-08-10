// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.
// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
// version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//details.
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::sync::Arc;
use tokio::sync::mpsc;
use tauri::Manager;
use anyhow::Result;

mod database;
use database as db;
mod scanning;
mod commands;
mod shared;
mod core;
mod modules;
mod analysis;

use crate::core::{engine::Engine, bootstrap::make_registry, types::Plan};
use crate::scanning::coordinator::ScanCoordinator;
use crate::database::DatabaseOperations;
use crate::db::Db;
use crate::core::registry::Registry;
use crate::shared::EventStreamer;

fn app_data_dir() -> std::path::PathBuf {
    tauri::api::path::app_data_dir(&tauri::Config::default())
        .unwrap_or(std::env::current_dir().unwrap())
}

fn open_db() -> Result<Db> {
    let db_dir = app_data_dir().join("LEGION2");
    std::fs::create_dir_all(&db_dir)?;
    Db::open(db_dir.join("network.db"))
}

#[tauri::command]
async fn engine_execute(
    app: tauri::AppHandle, 
    state: tauri::State<'_, Engine>, 
    plan: Plan
) -> Result<(), String> {
    state.execute(plan).await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    println!("LEGION2 starting up...");
    
    // Initialize database
    let db = open_db().expect("Failed to open database");
    let db_ops = Arc::new(DatabaseOperations::new(db));
    
    // Run migrations
    rusqlite::migrate!("./migrations").run(&db)
        .expect("Failed to run migrations");
    
    // Initialize event handling
    let (event_tx, mut event_rx) = mpsc::channel(1000);
    let event_streamer = Arc::new(EventStreamer::new());
    
    // Initialize scanner coordinator
    let coordinator = Arc::new(ScanCoordinator::new(
        db_ops.clone(),
        event_tx,
    ));

    // Bridge events to streamer
    let streamer_clone = event_streamer.clone();
    tokio::spawn(async move {
        log::info!("Event bridge task started");
        while let Some(event) = event_rx.recv().await {
            log::info!("Bridging event: {:?}", event.event_type);
            streamer_clone.send_event(event).await;
        }
        log::error!("Event bridge task ended - this should not happen");
    });
    
    tauri::Builder::default()
        .manage(db_ops)
        .manage(coordinator)
        .manage(event_streamer)
        .invoke_handler(tauri::generate_handler![
            engine_execute,
            get_all_hosts,
            get_host_details,
            delete_host,
            batch_import_hosts,
            setup_event_stream,
            commands::scanner_commands::start_scan,
            commands::scanner_commands::cancel_scan,
            commands::scanner_commands::get_active_scans,
            commands::scanner_commands::get_scan_status,
            commands::scanner_commands::get_scan_results,
            commands::scanner_commands::get_scan_statistics,
            commands::scanner_commands::get_scan_progress,
            commands::scanner_commands::get_scanner_status,
            commands::scan_commands::start_network_scan,
            commands::scan_commands::cancel_network_scan,
            commands::scan_commands::get_scan_progress,
            commands::scan_commands::is_scanning,
            commands::scan_commands::get_scan_statistics,
            commands::scan_commands::scan_network_range,
            commands::host_commands::update_host_os_detection,
            commands::host_commands::get_host_by_ip,
            scan_with_masscan,
            scan_with_nmap,
            get_scanner_status,
            get_bin_directory_path,
            is_scanner_available,
            quick_network_scan,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}