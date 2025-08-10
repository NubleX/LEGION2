use crate::scanning::{
    engine::Engine,
    plan::Plan,
    registry::Registry,
    sinks::Db,
};
use tauri::{AppHandle, State};
use std::sync::Arc;

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
    let mut engine = Engine::new();
    
    // Create and add source
    let source = registry.create_source(&plan).await
        .map_err(|e| format!("Failed to create source: {}", e))?;
    engine.add_source(source);
    
    // Create and add sinks
    let sinks = registry.create_sinks(&plan)
        .map_err(|e| format!("Failed to create sinks: {}", e))?;
    
    for sink in sinks {
        engine.add_sink(sink);
    }
    
    // Execute in background task - return immediately while streaming
    tokio::spawn(async move {
        log::info!("Starting engine execution in background");
        
        match engine.run().await {
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