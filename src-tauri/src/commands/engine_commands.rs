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
use crate::plan::Plan;
use crate::database::Db;
use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

/// One command to rule them all - unified engine execution
#[tauri::command]
pub async fn engine_execute(
    plan: Plan,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<(), String> {
    log::info!("Engine execute called with plan: {:?}", plan);

    // Get database reference
    let db = state_db.inner().clone();

    // Create registry
    let registry = Registry::new(db, app);

    // Build engine from plan
    let engine = Engine { registry };

    // Execute in background task - return immediately while streaming
    tokio::spawn(async move {
        log::info!("Starting engine execution in background");

        match engine.execute(plan).await {
            Ok(_) => {
                log::info!("Engine execution completed successfully");
            }
            Err(e) => {
                log::error!("Engine execution failed: {}", e);
            }
        }
    });
    Ok(())
}

/// High-level scan configuration from frontend
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanConfig {
    pub targets: String,
    pub scan_type: String,
    pub ports: Option<String>, 
    pub use_masscan: bool,
    pub masscan_rate: Option<u64>,
    pub nmap_options: Option<Vec<String>>,
    pub modules: Option<Vec<String>>,
    pub enable_os_detection: Option<bool>,
    pub enable_service_detection: Option<bool>,
}

/// Start scan using Plan builders - this is the new preferred way
#[tauri::command]
pub async fn start_scan_with_config(
    config: ScanConfig,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<String, String> {
    log::info!("Starting scan with config: {:?}", config);
    
    let scan_id = Uuid::new_v4();
    let targets: Vec<&str> = config.targets
        .split(&[',', '\n'][..])
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();
    
    if targets.is_empty() {
        return Err("No valid targets specified".to_string());
    }
    
    let target = targets[0].to_string(); // Use first target for now
    let ports = config.ports.unwrap_or_else(|| "1-1000".to_string());
    
    // Use Plan builders based on scanner type and scan configuration
    let mut plan = match config.scan_type.as_str() {
        "comprehensive" => Plan::comprehensive(scan_id, target, ports),
        "os_detection" => Plan::os_detection(scan_id, target),
        _ => {
            if config.use_masscan {
                Plan::masscan(scan_id, target, ports, config.masscan_rate)
            } else {
                let extra_args = config.nmap_options.unwrap_or_default();
                Plan::nmap(scan_id, target, ports, extra_args)
            }
        }
    };
    
    // Add OS detection if requested
    if config.enable_os_detection.unwrap_or(false) {
        plan = plan.with_os_detection();
    }
    
    // Add service detection if requested
    if config.enable_service_detection.unwrap_or(false) && !config.use_masscan {
        plan = plan.with_extra_args(vec!["-sV".to_string()]);
    }
    
    // Add modules if specified
    if let Some(modules) = config.modules {
        plan = plan.with_modules(modules);
    }
    
    // Could add more builder methods here:
    // plan = plan.with_sink("json-export".to_string());
    
    log::info!("Created plan using builders: {:?}", plan);
    
    // Get database reference
    let db = state_db.inner().clone();
    
    // Create registry
    let registry = Registry::new(db, app);
    
    // Build engine from plan
    let engine = Engine { registry };
    
    // Execute in background task - return scan ID immediately 
    tokio::spawn(async move {
        log::info!("Starting engine execution in background");
        
        match engine.execute(plan).await {
            Ok(_) => {
                log::info!("Engine execution completed successfully");
            }
            Err(e) => {
                log::error!("Engine execution failed: {}", e);
            }
        }
    });
    
    Ok(scan_id.to_string())
}

/// Start OS detection scan for specific targets
#[tauri::command]
pub async fn start_os_detection_scan(
    targets: String,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<String, String> {
    log::info!("Starting OS detection scan for targets: {}", targets);
    
    let scan_id = Uuid::new_v4();
    let plan = Plan::os_detection(scan_id, targets);
    
    log::info!("Created OS detection plan: {:?}", plan);
    
    // Get database reference
    let db = state_db.inner().clone();
    
    // Create registry
    let registry = Registry::new(db, app);
    
    // Build engine from plan
    let engine = Engine { registry };
    
    // Execute in background task - return scan ID immediately 
    tokio::spawn(async move {
        log::info!("Starting OS detection engine execution in background");
        
        match engine.execute(plan).await {
            Ok(_) => {
                log::info!("OS detection execution completed successfully");
            }
            Err(e) => {
                log::error!("OS detection execution failed: {}", e);
            }
        }
    });
    
    Ok(scan_id.to_string())
}

/// Advanced scan configuration with module pipeline support
#[derive(Debug, Serialize, Deserialize)]
pub struct AdvancedScanConfig {
    pub targets: String,
    pub ports: String,
    pub scanner_type: String, // "masscan" or "nmap"
    pub rate: Option<u64>,
    pub nmap_args: Option<Vec<String>>,
    pub modules: Vec<String>, // e.g., ["port-classifier", "vuln-mapper"]
    pub extra_sinks: Option<Vec<String>>, // e.g., ["json-export", "xml-export"]
}

/// Example of advanced scan using full Plan builder capabilities
#[tauri::command]
pub async fn start_advanced_scan(
    config: AdvancedScanConfig,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<String, String> {
    log::info!("Starting advanced scan with config: {:?}", config);
    
    let scan_id = Uuid::new_v4();
    
    // Demonstrate the full builder pattern
    let plan = match config.scanner_type.as_str() {
        "masscan" => {
            Plan::masscan(scan_id, config.targets, config.ports, config.rate)
                .with_modules(config.modules)
        }
        "nmap" => {
            Plan::nmap(scan_id, config.targets, config.ports, config.nmap_args.unwrap_or_default())
                .with_modules(config.modules)
                .with_rate(config.rate.unwrap_or(1000))  // Set rate even for nmap
        }
        _ => return Err(format!("Unknown scanner type: {}", config.scanner_type))
    }
    // Add extra sinks if specified
    .with_sink("xml-export".to_string())  // Example: always add XML export for advanced scans
    .with_extra_args(vec!["--verbose".to_string()]); // Example: always be verbose
    
    log::info!("Created advanced plan with full builder chain: {:?}", plan);
    
    // Rest is the same...
    let db = state_db.inner().clone();
    let registry = Registry::new(db, app);
    let engine = Engine { registry };
    
    tokio::spawn(async move {
        if let Err(e) = engine.execute(plan).await {
            log::error!("Advanced scan execution failed: {}", e);
        }
    });
    
    Ok(scan_id.to_string())
}
