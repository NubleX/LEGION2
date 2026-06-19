// Backup of original main.rs
// LEGION2 - A free and open-source penetration testing tool.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use crate::database::Db;
use crate::analysis::AnalysisEngine;
use anyhow::Result;
use std::sync::Arc;
use tauri::{Manager, RunEvent};

mod analysis;
mod commands;
mod core;
mod database;
mod modules;
mod network;
mod offensive;
mod os;
mod plan;
mod scanners;
mod session_state;
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
    let db_for_setup = db.clone();

    tauri::Builder::default()
        .setup(move |app| {
            let analysis_engine = AnalysisEngine::with_ui(db_for_setup.clone(), app.handle().clone());
            app.manage(analysis_engine);

            // Start periodic background task to refresh all hosts every 27 seconds
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(27));
                loop {
                    interval.tick().await;
                    log::debug!("Emitting refresh_all_hosts event");
                    if let Err(e) = tauri::Emitter::emit(&app_handle, "refresh_all_hosts", ()) {
                        log::warn!("Failed to emit refresh_all_hosts event: {}", e);
                    }
                }
            });
            Ok(())
        })
        .manage(db.clone())
        .invoke_handler(tauri::generate_handler![
            commands::engine_commands::engine_execute,
            commands::engine_commands::engine_cancel_scan,
            commands::engine_commands::engine_reset,
            commands::engine_commands::engine_clear_active_targets,
            commands::engine_commands::engine_get_state,
            commands::host_commands::get_all_hosts,
            commands::host_commands::get_hosts_in_range,
            commands::host_commands::get_host_details,
            commands::host_commands::get_host_by_ip,
            commands::host_commands::get_host_ports_detailed,
            commands::host_commands::get_host_services,
            commands::host_commands::get_service_cves,
            commands::host_commands::enrich_service_osint,
            commands::host_commands::delete_host,
            commands::host_commands::clear_all_hosts,
            commands::host_commands::batch_import_hosts,
            commands::host_commands::update_host_os_detection,
            commands::analysis_commands::analyze_host,
            commands::analysis_commands::analyze_network,
            commands::analysis_commands::get_active_analyses,
            commands::analysis_commands::get_host_vulnerabilities,
            commands::analysis_commands::get_all_vulnerabilities,
            commands::analysis_commands::analyze_host_vulnerabilities,
            commands::analysis_commands::get_vulnerability_stats,
            commands::analysis_commands::get_service_statistics,
            commands::analysis_commands::import_nmap_xml,
            commands::analysis_commands::parse_scan_session,
            commands::analysis_commands::get_latest_session_analytics,
            commands::cve_commands::search_cves_by_product,
            commands::cve_commands::fetch_cve,
            commands::cve_commands::get_all_cves,
            commands::cve_commands::get_cve_risk_assessment,
            commands::cve_commands::search_and_store_cves,
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
            commands::plan_commands::create_massmap_plan,
            commands::plan_commands::create_netsniffer_plan,
            commands::os_commands::check_scanner_capabilities,
            commands::os_commands::set_scanner_capabilities,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app, event| {
            if let RunEvent::ExitRequested { .. } = event {
                log::info!("App exit requested — killing scanner child processes");
                tauri::async_runtime::block_on(async {
                    commands::engine_commands::shutdown_kill_children().await;
                });
            }
        });
}
