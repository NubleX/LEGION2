use std::sync::Arc;
use anyhow::Result;
use tauri::AppHandle;

use super::registry::Registry;
use crate::db::Db;

/// Bootstrap function to create and configure the registry
pub fn make_registry(db: Arc<Db>, app_handle: AppHandle) -> Result<Registry> {
    Ok(Registry::new(db, app_handle))
}