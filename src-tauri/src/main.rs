// Backup of original main.rs
// LEGION2 - A free and open-source penetration testing tool.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use crate::database::Db;
use anyhow::Result;
use std::sync::Arc;

mod analysis;
mod commands;
mod core;
mod database;
mod modules;
mod network;
mod os;
mod plan;
mod scanners;
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

    // Initialize database
    let db = Arc::new(open_db().expect("Failed to open database"));

    tauri::Builder::default()
        .manage(db.clone())
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
            commands::host_commands::update_host_os_detection,
            commands::host_commands::get_host_by_ip,
            commands::analysis_commands::get_host_vulnerabilities,
            commands::netsniffer_commands::lookup_mac_vendor,
            commands::netsniffer_commands::log_network_artifact,
            commands::netsniffer_commands::start_network_monitoring,
            commands::netsniffer_commands::stop_network_monitoring,
            commands::netsniffer_commands::get_vendor_statistics,
            commands::netsniffer_commands::parse_xml_for_mac_enrichment,
            commands::plan_commands::create_masscan_plan,
            commands::plan_commands::create_nmap_plan,
            commands::plan_commands::create_comprehensive_plan,
            commands::plan_commands::create_os_detection_plan,
            commands::plan_commands::plan_with_os_detection,
            commands::plan_commands::plan_with_extra_args,
            commands::plan_commands::plan_with_modules,
            commands::plan_commands::plan_with_rate,
            commands::plan_commands::plan_with_sink,
            commands::plan_commands::get_available_modules,
            commands::plan_commands::create_plan_with_modules,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
