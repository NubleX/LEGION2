// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::core::{engine::Engine, registry::Registry};
use crate::database::Db;
use crate::plan::Plan;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, State};
use tokio::sync::Mutex;

// Global scan cancellation flag
static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

// Global engine instance to persist state between calls
lazy_static::lazy_static! {
    static ref GLOBAL_ENGINE: Arc<Mutex<Option<Engine>>> = Arc::new(Mutex::new(None));
}

/// One command to rule them all - unified engine execution
#[tauri::command]
pub async fn engine_execute(
    plan: Plan,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<(), String> {
    log::info!("Engine execute called with plan: {:?}", plan);

    // Reset cancellation flag for new scan
    reset_scan_cancellation();

    // Get or create engine instance
    let mut engine_guard = GLOBAL_ENGINE.lock().await;
    let engine = match engine_guard.as_ref() {
        Some(existing_engine) => {
            // Check if engine is ready for new scan
            if existing_engine.is_ready().await {
                log::info!("Using existing engine in ready state");
                existing_engine.clone()
            } else {
                log::info!("Engine not ready, resetting and preparing for new scan");
                existing_engine.reset().await.map_err(|e| e.to_string())?;
                existing_engine.clone()
            }
        }
        None => {
            log::info!("Creating new engine instance");

            // Build engine from registry, wire Arc<Db> into DbSink
            let registry = Registry::new(state_db.inner().clone(), app);

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
            let new_engine = Engine::new(registry);
            *engine_guard = Some(new_engine.clone());
            new_engine
        }
    };

    // Release the lock before spawning background task
    drop(engine_guard);

    // Check if engine is ready before spawning (double-check after lock release)
    if !engine.is_ready().await {
        let current_state = engine.get_state().await;
        return Err(format!(
            "Engine not ready for new scan. Current state: {:?}",
            current_state
        ));
    }

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

/// Reset the engine to allow new scans
#[tauri::command]
pub async fn engine_reset() -> Result<(), String> {
    log::info!("Engine reset requested");

    // Reset cancellation flag
    reset_scan_cancellation();

    let engine_guard = GLOBAL_ENGINE.lock().await;
    if let Some(engine) = engine_guard.as_ref() {
        engine.reset().await.map_err(|e| e.to_string())?;
        log::info!("Engine reset completed");
    } else {
        log::info!("No engine instance to reset");
    }

    Ok(())
}

/// Get current engine state
#[tauri::command]
pub async fn engine_get_state() -> Result<String, String> {
    let engine_guard = GLOBAL_ENGINE.lock().await;
    if let Some(engine) = engine_guard.as_ref() {
        let state = engine.get_state().await;
        Ok(format!("{:?}", state))
    } else {
        Ok("NoEngine".to_string())
    }
}
