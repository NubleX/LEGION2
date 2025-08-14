use anyhow::Result;
use std::sync::Arc;
use tauri::State;

use crate::database::DatabaseOperations;
use crate::shared::Host;

#[tauri::command]
pub async fn db_batch_upsert_hosts(
    db: State<'_, Arc<DatabaseOperations>>,
    hosts: Vec<Host>,
) -> Result<usize, String> {
    db.batch_upsert_hosts(&hosts)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn db_search_hosts(
    db: State<'_, Arc<DatabaseOperations>>,
    term: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<Host>, String> {
    db.search_hosts_paged(term.as_deref(), limit.unwrap_or(100), offset.unwrap_or(0))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn db_update_host_tags(
    db: State<'_, Arc<DatabaseOperations>>,
    host_id: String,
    tags: Vec<String>,
) -> Result<(), String> {
    db.update_host_tags(&host_id, tags)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn db_update_host_notes(
    db: State<'_, Arc<DatabaseOperations>>,
    host_id: String,
    notes: Option<String>,
) -> Result<(), String> {
    db.update_host_notes(&host_id, notes)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn db_get_host_by_ip(
    db: State<'_, Arc<DatabaseOperations>>,
    ip: String,
) -> Result<Option<Host>, String> {
    db.try_get_host_by_ip(&ip).await.map_err(|e| e.to_string())
}
