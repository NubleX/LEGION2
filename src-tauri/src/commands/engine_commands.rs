// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::core::{engine::Engine, registry::Registry};
use crate::core::sinks::{DoneEvent, ErrorEvent};
use crate::database::Db;
use crate::plan::Plan;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

#[cfg(unix)]
use libc;

// Global scan cancellation flag
static SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);

// Global registry of child scanner PIDs — killed immediately on cancel
lazy_static::lazy_static! {
    static ref CHILD_PIDS: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    static ref GLOBAL_ENGINE: Arc<Mutex<Option<Engine>>> = Arc::new(Mutex::new(None));
    static ref ACTIVE_SCAN_TARGETS: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
}

/// Register a child scanner process PID so it can be killed on cancel
pub async fn register_child_pid(pid: u32) {
    CHILD_PIDS.lock().await.insert(pid);
    log::debug!("Registered child scanner PID {}", pid);
}

/// Remove a PID when its process exits normally
pub async fn unregister_child_pid(pid: u32) {
    CHILD_PIDS.lock().await.remove(&pid);
    log::debug!("Unregistered child scanner PID {}", pid);
}

/// Kill all registered child scanner processes immediately (SIGKILL)
async fn kill_all_children() {
    let pids: Vec<u32> = {
        let mut guard = CHILD_PIDS.lock().await;
        let pids: Vec<u32> = guard.iter().copied().collect();
        guard.clear();
        pids
    };
    for pid in pids {
        log::info!("Killing scanner child PID {}", pid);
        #[cfg(unix)]
        kill_process_tree(pid);
        #[cfg(not(unix))]
        log::warn!("Process kill not implemented on this platform (PID {})", pid);
    }
}

#[cfg(unix)]
fn kill_process_tree(pid: u32) {
    // Negative PID kills the process group when spawned with process_group(0)
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

/// Set active scan target range for scoped background analysis
pub async fn set_active_scan_targets(targets: Option<String>) {
    *ACTIVE_SCAN_TARGETS.lock().await = targets;
}

/// Get active scan target range (if any)
pub async fn get_active_scan_targets() -> Option<String> {
    ACTIVE_SCAN_TARGETS.lock().await.clone()
}

/// Kill all scanner children on app shutdown or cancel
pub async fn shutdown_kill_children() {
    cancel_current_scan();
    kill_all_children().await;
    set_active_scan_targets(None).await;
}

/// One command to rule them all - unified engine execution
#[tauri::command]
pub async fn engine_execute(
    plan: Plan,
    state_db: State<'_, Arc<Db>>,
    app: AppHandle,
) -> Result<(), String> {
    log::info!("Engine execute called with plan: {:?}", plan);

    // Clone app handle upfront - make_registry may consume the original
    let app_handle = app.clone();

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
            // Use make_registry bootstrap function for consistent initialization
            let registry = crate::core::bootstrap::make_registry(state_db.inner().clone(), app)
                .map_err(|e| format!("Failed to create registry: {}", e))?;

            // Initialize all standard components in registry
            if let Err(e) = registry.initialize_standard_components().await {
                log::error!("Failed to initialize registry components: {}", e);
                return Err(format!("Registry initialization failed: {}", e));
            }

            // Start continuous discovery manager for recursive discovery
            let discovery_manager = registry.get_discovery_manager();
            if let Err(e) = discovery_manager.start_continuous_discovery().await {
                log::warn!("Failed to start continuous discovery manager: {}", e);
            } else {
                log::info!("🔍 Continuous recursive discovery manager started");
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
            "A scan is already in progress (engine state: {:?}). \
             Wait for it to finish or click Cancel before starting another scan.",
            current_state
        ));
    }

    // Track active scan targets for scoped background analysis (skip netsniffer / empty targets)
    if !plan.targets.trim().is_empty() {
        set_active_scan_targets(Some(plan.targets.clone())).await;
    }

    // Capture scan_id for error-path event emission (app_handle already cloned at top)
    let scan_id = plan.scan_id.to_string();

    // Execute in background task - return immediately while streaming
    tokio::spawn(async move {
        log::info!("Starting engine execution in background");

        match engine.execute(plan).await {
            Ok(_) => {
                log::info!("Engine execution completed successfully");
            }
            Err(e) => {
                log::error!("Engine execution failed: {}", e);

                // Emit obs:error so the UI shows an error message
                let _ = app_handle.emit("obs:error", &ErrorEvent {
                    message: format!("Scan failed: {}", e),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });

                // Emit obs:done so the frontend unblocks scanInProgress
                let _ = app_handle.emit("obs:done", &DoneEvent { scan_id: scan_id.clone() });
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
    shutdown_kill_children().await;
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

/// Clear active scan target range (called when all scan phases complete)
#[tauri::command]
pub async fn engine_clear_active_targets() {
    set_active_scan_targets(None).await;
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
