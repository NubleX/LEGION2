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