use anyhow::Result;
use std::sync::Arc;
use tauri::AppHandle;

use super::registry::Registry;
use crate::analysis::AnalysisEngine;
use crate::database::Db;

/// Bootstrap function to create and configure the registry
pub fn make_registry(
    db: Arc<Db>,
    app_handle: AppHandle,
    analysis_engine: Arc<AnalysisEngine>,
) -> Result<Registry> {
    Ok(Registry::new(db, app_handle, analysis_engine))
}
