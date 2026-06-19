// LEGION2 - Recursive Discovery Manager
// Copyright (c) 2025 NubleX / Igor Dunaev
// 
// Continuously monitors discoveries and recursively triggers new scans
// to build comprehensive network topology and knowledge base

use crate::core::registry::Registry;
use crate::database::Db;
use anyhow::Result;
use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tauri::AppHandle;

/// Manages recursive discovery - automatically triggers scans on new discoveries
pub struct DiscoveryManager {
    registry: Arc<Registry>,
    db: Arc<Db>,
    app_handle: Option<AppHandle>,
    discovered_hosts: Arc<Mutex<HashSet<String>>>,
    scanned_hosts: Arc<Mutex<HashSet<String>>>,
    pending_scans: Arc<Mutex<HashMap<String, u64>>>, // host -> timestamp
    scan_cooldown: Duration,
    last_topology_update: Arc<Mutex<Option<std::time::Instant>>>,
}

impl DiscoveryManager {
    pub fn new(registry: Arc<Registry>, db: Arc<Db>) -> Self {
        Self {
            registry,
            db,
            app_handle: None,
            discovered_hosts: Arc::new(Mutex::new(HashSet::new())),
            scanned_hosts: Arc::new(Mutex::new(HashSet::new())),
            pending_scans: Arc::new(Mutex::new(HashMap::new())),
            scan_cooldown: Duration::from_secs(300), // 5 minute cooldown per host
            last_topology_update: Arc::new(Mutex::new(None)),
        }
    }
    
    pub fn with_app_handle(mut self, app_handle: AppHandle) -> Self {
        self.app_handle = Some(app_handle);
        self
    }

    /// Start continuous discovery loop
    pub async fn start_continuous_discovery(&self) -> Result<()> {
        log::info!("🔍 Starting continuous recursive discovery manager");
        
        // Load existing hosts from database
        self.load_existing_hosts().await?;
        
        // Start periodic scan trigger task
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30)); // Check every 30 seconds
            loop {
                interval.tick().await;
                if let Err(e) = manager.process_pending_scans().await {
                    log::error!("Error processing pending scans: {}", e);
                }
            }
        });
        
        // Start periodic topology update task
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Update every minute
            loop {
                interval.tick().await;
                if let Err(e) = manager.update_network_topology().await {
                    log::warn!("Error updating network topology: {}", e);
                }
            }
        });
        
        Ok(())
    }

    /// Handle new host discovery - trigger recursive scans
    pub async fn on_host_discovered(&self, host_ip: &str) -> Result<()> {
        let mut discovered = self.discovered_hosts.lock().await;
        
        // Check if this is a new host
        if discovered.contains(host_ip) {
            return Ok(()); // Already discovered
        }
        
        discovered.insert(host_ip.to_string());
        drop(discovered);
        
        log::info!("🆕 New host discovered: {} - triggering recursive scans", host_ip);
        
        // Schedule scans for this new host
        self.schedule_host_scans(host_ip).await?;
        
        Ok(())
    }

    /// Handle new service discovery - trigger deeper service scans
    pub async fn on_service_discovered(&self, host_ip: &str, port: u16, service: &str) -> Result<()> {
        log::debug!("🔍 Service discovered: {}:{} ({}) - considering deeper scan", host_ip, port, service);
        
        // For critical services, trigger deeper scans
        let critical_services = ["http", "https", "ssh", "ftp", "smb", "rdp", "vnc", "mysql", "postgresql"];
        if critical_services.iter().any(|s| service.to_lowercase().contains(s)) {
            log::info!("🎯 Critical service {}:{} detected - scheduling deep scan", host_ip, port);
            self.schedule_service_scan(host_ip, port, service).await?;
        }
        
        Ok(())
    }

    /// Schedule comprehensive scans for a newly discovered host.
    /// Autonomous recursive scanning is disabled — all scanning is user-initiated only.
    async fn schedule_host_scans(&self, _host_ip: &str) -> Result<()> {
        Ok(())
    }

    /// Schedule deep scan for a specific service.
    /// Autonomous scanning is disabled — all scanning is user-initiated only.
    async fn schedule_service_scan(&self, _host_ip: &str, _port: u16, _service: &str) -> Result<()> {
        Ok(())
    }

    /// Process pending scans - trigger actual scan execution
    async fn process_pending_scans(&self) -> Result<()> {
        let pending = self.pending_scans.lock().await;
        let scanned = self.scanned_hosts.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut to_scan = Vec::new();
        
        // Collect hosts that are ready to scan (past cooldown)
        for (host_ip, scheduled_time) in pending.iter() {
            if scanned.contains(host_ip) {
                continue; // Already scanned
            }
            
            let elapsed = now.saturating_sub(*scheduled_time);
            if elapsed >= self.scan_cooldown.as_secs() {
                to_scan.push(host_ip.clone());
            }
        }
        
        drop(pending);
        drop(scanned);
        
        // Execute scans for ready hosts
        for host_ip in to_scan {
            if let Err(e) = self.execute_recursive_scans(&host_ip).await {
                log::error!("Failed to execute recursive scans for {}: {}", host_ip, e);
            } else {
                let mut scanned = self.scanned_hosts.lock().await;
                scanned.insert(host_ip.clone());
                let mut pending = self.pending_scans.lock().await;
                pending.remove(&host_ip);
                log::info!("✅ Completed recursive scans for host: {}", host_ip);
            }
        }
        
        Ok(())
    }

    /// Execute comprehensive recursive scans for a host.
    /// Autonomous recursive scanning is disabled — all scanning is user-initiated only.
    async fn execute_recursive_scans(&self, _host_ip: &str) -> Result<()> {
        Ok(())
    }

    /// Update network topology based on all discoveries
    async fn update_network_topology(&self) -> Result<()> {
        let mut last_update = self.last_topology_update.lock().await;
        let now = std::time::Instant::now();
        
        // Only update if enough time has passed
        if let Some(last) = *last_update {
            if now.duration_since(last) < Duration::from_secs(60) {
                return Ok(());
            }
        }
        
        *last_update = Some(now);
        drop(last_update);
        
        log::debug!("🗺️  Updating network topology from discoveries");
        
        // Get all hosts from database
        let hosts = self.db.get_all_hosts().await?;
        let discovered = self.discovered_hosts.lock().await;
        
        log::info!("📊 Network topology: {} total hosts, {} newly discovered", 
                   hosts.len(), discovered.len());
        
        // Trigger analysis engine to build topology (only during active user scan)
        let targets = crate::commands::engine_commands::get_active_scan_targets().await;
        let Some(targets) = targets else {
            log::debug!("No active scan — skipping periodic vulnerability analysis");
            return Ok(());
        };

        let analysis_engine = self.registry.get_analysis_engine();
        if let Err(e) = analysis_engine.analyze_network(Some(&targets)).await {
            log::warn!("Failed to analyze network topology: {}", e);
        }
        
        Ok(())
    }

    /// Load existing hosts from database
    async fn load_existing_hosts(&self) -> Result<()> {
        let hosts = self.db.get_all_hosts().await?;
        let mut discovered = self.discovered_hosts.lock().await;
        
        for host in hosts {
            // Host struct has ip field directly
            let ip = host.ip.clone();
            if !ip.is_empty() {
                discovered.insert(ip);
            }
        }
        
        log::info!("📚 Loaded {} existing hosts from database", discovered.len());
        Ok(())
    }
}

impl Clone for DiscoveryManager {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            db: self.db.clone(),
            app_handle: self.app_handle.clone(),
            discovered_hosts: Arc::clone(&self.discovered_hosts),
            scanned_hosts: Arc::clone(&self.scanned_hosts),
            pending_scans: Arc::clone(&self.pending_scans),
            scan_cooldown: self.scan_cooldown,
            last_topology_update: Arc::clone(&self.last_topology_update),
        }
    }
}

