use std::collections::{HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

use serde::Deserialize;
use tauri::AppHandle;
use uuid::Uuid;

use crate::core::{engine::Engine, registry::Registry};
use crate::database::Db;
use crate::plan::{Plan, ScanType};

/// Options for a scan request
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    pub ports: Option<String>,
    pub rate: Option<u32>,
    pub extra_args: Option<Vec<String>>,
    pub use_masscan: Option<bool>,
}

/// Request to start a scan
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub target: String,
    pub scan_type: ScanType,
    pub options: Option<ScanOptions>,
}

/// Coordinates active scans and tracks their state
pub struct ScanCoordinator {
    db: Arc<Db>,
    active_scans: Arc<Mutex<HashSet<String>>>,
}

impl ScanCoordinator {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            active_scans: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Start a scan using the new engine/registry system
    pub async fn start_scan(
        &self,
        app: AppHandle,
        request: ScanRequest,
    ) -> Result<String, String> {
        let scan_id = Uuid::new_v4();

        let ports = request
            .options
            .as_ref()
            .and_then(|o| o.ports.clone())
            .unwrap_or_else(|| "1-1000".to_string());

        let extra = request
            .options
            .as_ref()
            .and_then(|o| o.extra_args.clone())
            .unwrap_or_default();

        let rate = request
            .options
            .as_ref()
            .and_then(|o| o.rate)
            .map(|r| r as u64);

        // Use the use_masscan field to decide scanner type
        let plan = if request
            .options
            .as_ref()
            .and_then(|o| o.use_masscan)
            .unwrap_or(false)
        {
            // Masscan selected - use rate if provided
            let masscan_rate = rate.unwrap_or(1000); // Default masscan rate
            Plan::masscan(scan_id, request.target.clone(), ports.clone(), Some(masscan_rate))
                .with_extra_args(extra)
        } else {
            // Use nmap with scan type-specific configuration
            match request.scan_type {
                ScanType::Comprehensive => {
                    Plan::comprehensive(scan_id, request.target.clone(), ports.clone())
                        .with_extra_args(extra)
                }
                ScanType::Discovery => {
                    Plan::os_detection(scan_id, request.target.clone())
                        .with_extra_args(extra)
                }
                ScanType::Stealth => {
                    Plan::nmap(scan_id, request.target.clone(), ports.clone(), 
                              vec!["-sS".to_string(), "-T2".to_string(), "-f".to_string()])
                        .with_extra_args(extra)
                }
                ScanType::Quick => {
                    Plan::nmap(scan_id, request.target.clone(), ports.clone(),
                              vec!["-T4".to_string(), "-F".to_string()])
                        .with_extra_args(extra)
                }
                _ => {
                    // Default nmap scan
                    Plan::nmap(scan_id, request.target.clone(), ports.clone(), extra)
                }
            }
        };

        let mut registry = Registry::new(self.db.clone(), app);
        
        // Initialize registry components
        if let Err(e) = registry.initialize_standard_components().await {
            log::error!("Failed to initialize coordinator registry: {}", e);
            return Err(format!("Registry initialization failed: {}", e));
        }
        
        let engine = Engine { registry };

        {
            let mut active = self.active_scans.lock().await;
            active.insert(scan_id.to_string());
        }

        let active_scans = self.active_scans.clone();
        tokio::spawn(async move {
            if let Err(e) = engine.execute(plan).await {
                log::error!("Engine execution failed: {}", e);
            }
            let mut active = active_scans.lock().await;
            active.remove(&scan_id.to_string());
        });

        Ok(scan_id.to_string())
    }

    /// Cancel a running scan (placeholder)
    pub async fn cancel_scan(&self, scan_id: String) -> Result<(), String> {
        let mut active = self.active_scans.lock().await;
        active.remove(&scan_id);
        // TODO: add actual cancellation logic
        Ok(())
    }

    /// Get IDs of active scans
    pub async fn get_active_scans(&self) -> Result<Vec<String>, String> {
        let active = self.active_scans.lock().await;
        Ok(active.iter().cloned().collect())
    }

    /// Get progress for a specific scan (placeholder)
    pub async fn get_scan_progress(&self, _scan_id: String) -> Result<String, String> {
        Ok("{}".to_string())
    }

    /// Get aggregated statistics for all scans (placeholder)
    pub async fn get_scan_statistics(&self) -> Result<String, String> {
        Ok("{}".to_string())
    }
}

