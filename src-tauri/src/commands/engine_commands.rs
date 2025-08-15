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

use crate::analysis::AnalysisEngine;
use crate::core::{engine::Engine, registry::Registry};
use crate::database::Db;
use crate::plan::Plan;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, State};

// Global scan cancellation flag
static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

/// One command to rule them all - unified engine execution
#[tauri::command]
pub async fn engine_execute(
    plan: Plan,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<(), String> {
    log::info!("Engine execute called with plan: {:?}", plan);

    // Build engine from registry, wire Arc<Db> into DbSink
    let mut registry = Registry::new(state_db.inner().clone(), app);
    
    // Initialize all standard components in registry
    if let Err(e) = registry.initialize_standard_components().await {
        log::error!("Failed to initialize registry components: {}", e);
        return Err(format!("Registry initialization failed: {}", e));
    }
    
    // Log available components
    let (sources, sinks, transforms) = registry.list_components();
    log::info!("Available sources: {:?}", sources);
    log::info!("Available sinks: {:?}", sinks);
    log::info!("Available transforms: {:?}", transforms);

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

/// Check if scan has been cancelled
pub fn is_scan_cancelled() -> bool {
    SCAN_CANCELLED.load(Ordering::Relaxed)
}

/// Reset cancellation flag for new scans
pub fn reset_scan_cancellation() {
    SCAN_CANCELLED.store(false, Ordering::Relaxed);
}

/// Set scan cancellation flag
pub fn cancel_current_scan() {
    SCAN_CANCELLED.store(true, Ordering::Relaxed);
}

/// Simple cancel scan command for the unified engine
#[tauri::command]
pub async fn engine_cancel_scan() -> Result<(), String> {
    log::info!("Engine scan cancellation requested");
    cancel_current_scan();
    Ok(())
}
