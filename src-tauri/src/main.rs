// Backup of original main.rs
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

use crate::analysis::AnalysisEngine;
use crate::database::Db;
use crate::scanning::coordinator::ScanCoordinator;
use anyhow::Result;
use std::{path::PathBuf, sync::Arc};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
    Manager,
};

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
    // Use app-local data directory for encrypted database
    // Store in a hidden subdirectory within the app
    std::env::current_exe()
        .unwrap_or_else(|_| std::env::current_dir().unwrap().join("legion2"))
        .parent()
        .unwrap()
        .join(".legion2_data")
}

fn open_db() -> Result<Db> {
    let db_dir = app_data_dir();
    std::fs::create_dir_all(&db_dir)?;
    let db_path = db_dir.join("network.db");
    let db = Db::open(db_path)?;
    Ok(db)
}

// engine_execute is now handled in commands::engine_commands

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    println!("LEGION2 starting up...");

    tauri::Builder::default()
        .setup(|app| {
            // Synchronous setup: tray, state, etc.
            let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.png"))
                .expect("Failed to load tray icon");

            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&quit])?;

            TrayIconBuilder::with_id("tray")
                .icon(icon)
                .menu(&menu)
                .on_menu_event(|app, event| {
                    if event.id == "quit" {
                        app.exit(0);
                    }
                })
                .build(app)?;

            // Synchronous state management
            let db_dir = app_data_dir();
            std::fs::create_dir_all(&db_dir).expect("Failed to create database directory");
            let db_path = db_dir.join("network.db");
            let db = Arc::new(Db::open(db_path).expect("Failed to open database"));
            let analysis_engine = AnalysisEngine::new(db.clone());

            app.manage(db.clone());
            app.manage(analysis_engine);

            // Spawn async tasks if needed, but do NOT use `app` inside
            tauri::async_runtime::spawn(async {
                // Async work here, but don't touch `app`
                if let Err(e) = modules::init() {
                    log::error!("Failed to initialize modules: {}", e);
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::engine_commands::engine_execute,
            commands::engine_commands::engine_cancel_scan,
            commands::engine_commands::engine_reset,
            commands::engine_commands::engine_get_state,
            commands::host_commands::get_all_hosts,
            commands::host_commands::get_host_details,
            commands::host_commands::get_host_by_ip,
            commands::host_commands::get_host_ports_detailed,
            commands::host_commands::delete_host,
            commands::host_commands::batch_import_hosts,
            commands::host_commands::update_host_tags,
            commands::analysis_commands::analyze_host,
            commands::analysis_commands::analyze_network,
            commands::analysis_commands::get_active_analyses,
            commands::analysis_commands::get_host_vulnerabilities,
            commands::analysis_commands::get_all_vulnerabilities,
            commands::analysis_commands::analyze_host_vulnerabilities,
            commands::analysis_commands::get_vulnerability_stats,
            commands::plan_commands::create_masscan_plan,
            commands::plan_commands::create_nmap_plan,
            commands::plan_commands::create_comprehensive_plan,
            commands::plan_commands::create_os_detection_plan,
            commands::plan_commands::plan_with_os_detection,
            commands::plan_commands::plan_with_extra_args,
            commands::plan_commands::plan_with_modules,
            commands::plan_commands::plan_with_rate,
            commands::plan_commands::plan_with_sink,
            commands::plan_commands::get_scan_types,
            commands::plan_commands::get_scan_timings,
            commands::plan_commands::create_port_range,
            commands::plan_commands::parse_protocol,
            commands::plan_commands::parse_port_state,
            commands::plan_commands::get_available_modules,
            commands::plan_commands::create_plan_with_modules,
            commands::scanner_commands::start_coordinated_scan,
            commands::scanner_commands::start_masscan_scan,
            commands::scanner_commands::start_nmap_scan,
            commands::scanner_commands::get_scanner_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
