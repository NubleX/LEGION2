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

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::sync::Arc;
use tokio::sync::mpsc;
use sqlx::SqlitePool;

mod database;
mod scanning;
mod commands;
mod shared;
mod utils;

use database::DatabaseOperations;
use scanning::{coordinator::ScanCoordinator, events::EventStreamer};
use commands::{scan_commands::*, host_commands::*, event_commands::*, scanner_commands::*};

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    println!("LEGION2 starting up...");
    
    // Initialize database
    let db_pool = SqlitePool::connect("sqlite:legion2.db").await
        .expect("Failed to connect to database");
    
    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await
        .expect("Failed to run migrations");
    
    let db_ops = Arc::new(DatabaseOperations::new(db_pool));
    
    // Initialize event streamer
    let event_streamer = Arc::new(EventStreamer::new());
    
    // Initialize scanner coordinator
    let (event_tx, mut event_rx) = mpsc::channel(1000);
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
            get_all_hosts,
            get_host_details,
            delete_host,
            batch_import_hosts,
            setup_event_stream,
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