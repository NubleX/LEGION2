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

#[derive(Clone)]
pub struct AppState {
    pub scan_coordinator: Arc<ScanCoordinator>,
    pub scan_results: Arc<RwLock<Vec<ScanResult>>>,
    pub database: Arc<Database>,
}

async fn initialize_database() -> Result<Arc<Database>> {
    // Create database directory if it doesn't exist
    tokio::fs::create_dir_all("data").await?;
    
    let database = Database::new("sqlite:data/legion2.db").await?;
    Ok(Arc::new(database))
}

async fn setup_result_handler(
    results_storage: Arc<RwLock<Vec<ScanResult>>>,
    mut results_rx: mpsc::Receiver<ScanResult>,
    window: tauri::Window,
) {
    while let Some(result) = results_rx.recv().await {
        // Store in memory
        {
            let mut results = results_storage.write().await;
            results.push(result.clone());
        }
        
        // Emit to frontend
        let _ = window.emit("scan-result", &result);
        
        // Log completion
        println!("Scan completed for {}: {} open ports", 
            result.target_id, result.open_ports.len());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
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
            let window = app.get_window("main").unwrap();
            
            // Setup result handler
            tokio::spawn(setup_result_handler(
                scan_results,
                results_rx,
                window,
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

// Additional Cargo.toml dependencies
/*
[dependencies]
tauri = { version = "1.5", features = ["api-all"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "sqlite", "chrono", "uuid", "migrate"] }
uuid = { version = "1.0", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
anyhow = "1.0"
thiserror = "1.0"
regex = "1.10"
xml-rs = "0.8"
cidr = "0.2"
ipnet = "2.9"
futures = "0.3"
env_logger = "0.10"
log = "0.4"
*/