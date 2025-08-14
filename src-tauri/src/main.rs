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

use crate::database::Db;
use crate::scanning::coordinator::ScanCoordinator;
use crate::shared::EventStreamer;
use anyhow::Result;
use rusqlite;
use std::sync::Arc;
use tokio::sync::mpsc;

mod analysis;
mod commands;
mod core;
mod database;
mod modules;
mod plan;
mod scanning;
mod shared;
mod utils;

fn app_data_dir() -> std::path::PathBuf {
    std::env::current_dir().unwrap().join("data")
}

fn open_db() -> Result<Db> {
    let db_dir = app_data_dir().join("LEGION2");
    std::fs::create_dir_all(&db_dir)?;
    let db_path = db_dir.join("network.db");
    let db = Db::open(db_path.to_str().unwrap())?;
    Ok(db)
}

// engine_execute is now handled in commands::engine_commands

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    println!("LEGION2 starting up...");

    // Initialize database

    let db = Arc::new(open_db().expect("Failed to open database"));

    tauri::Builder::default()
        .manage(db.clone())
        .invoke_handler(tauri::generate_handler![
            commands::engine_commands::engine_execute,
            commands::host_commands::get_all_hosts,
            commands::host_commands::get_host_details,
            commands::host_commands::delete_host,
            commands::host_commands::batch_import_hosts,
            commands::host_commands::update_host_os_detection,
            commands::host_commands::get_host_by_ip,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
