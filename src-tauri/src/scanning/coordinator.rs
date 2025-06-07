use super::*;
use crate::database::{Database, operations::*};
use crate::utils::{ProcessManager, InputValidator, NetworkUtils, OutputParser, RateLimiter};
use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock, Semaphore};
use std::sync::Arc;
use anyhow::Result;

pub struct ScanCoordinator {
    active_scans: Arc<RwLock<HashMap<Uuid, ScanHandle>>>,
    nmap_scanner: NmapScanner,
    masscan_scanner: MasscanScanner,
    database: Arc<Database>,
    process_manager: ProcessManager,
    rate_limiter: Arc<RateLimiter>,
    results_tx: mpsc::Sender<ScanResult>,
    scan_semaphore: Arc<Semaphore>,
}

#[derive(Debug)]
struct ScanHandle {
    target: ScanTarget,
    status: ScanStatus,
    cancel_tx: Option<mpsc::Sender<()>>,
    start_time: DateTime<Utc>,
}

impl ScanCoordinator {
    pub fn new(database: Arc<Database>, results_tx: mpsc::Sender<ScanResult>) -> Self {
        Self {
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            nmap_scanner: NmapScanner::new(5),
            masscan_scanner: MasscanScanner::new(3, 10000),
            database,
            process_manager: ProcessManager::new(300), // 5 min timeout
            rate_limiter: Arc::new(RateLimiter::new(100.0, 50.0)), // 100 capacity, 50/sec refill
            results_tx,
            scan_semaphore: Arc::new(Semaphore::new(10)), // Max 10 concurrent scans
        }
    }

    pub async fn start_scan(
        &self,
        target: ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<Uuid> {
        // Validate target
        InputValidator::validate_ip(&target.ip.to_string())?;
        
        let scan_id = target.id;
        let (cancel_tx, cancel_rx) = mpsc::channel(1);
        
        // Register scan
        {
            let mut scans = self.active_scans.write().await;
            scans.insert(scan_id, ScanHandle {
                target: target.clone(),
                status: ScanStatus::Queued,
                cancel_tx: Some(cancel_tx),
                start_time: Utc::now(),
            });
        }

        // Create database scan record
        let scan_record = ScanOperations::create(
            self.database.pool(),
            &format!("Scan {}", target.ip),
            &[target.ip],
            &format!("{:?}", target.scan_type),
        ).await?;

        // Spawn scan task
        let coordinator = self.clone();
        tokio::spawn(async move {
            let result = coordinator.execute_scan_with_cancellation(
                target, 
                progress_tx, 
                cancel_rx,
                &scan_record.id
            ).await;
            
            coordinator.handle_scan_completion(scan_id, result).await;
        });

        Ok(scan_id)
    }

    async fn execute_scan_with_cancellation(
        &self,
        target: ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
        mut cancel_rx: mpsc::Receiver<()>,
        scan_record_id: &str,
    ) -> Result<ScanResult> {
        let _permit = self.scan_semaphore.acquire().await?;
        
        // Update status to running
        self.update_scan_status(&target.id, ScanStatus::Running).await;
        ScanOperations::update_status(self.database.pool(), scan_record_id, "running").await?;

        // Execute scan based on type
        let scan_future = match target.scan_type {
            ScanType::Quick => self.execute_quick_scan(target, progress_tx).boxed(),
            ScanType::Comprehensive => self.execute_comprehensive_scan(target, progress_tx).boxed(),
            ScanType::Stealth => self.execute_stealth_scan(target, progress_tx).boxed(),
            ScanType::Custom { .. } => self.execute_custom_scan(target, progress_tx).boxed(),
        };

        // Race between scan execution and cancellation
        tokio::select! {
            result = scan_future => {
                ScanOperations::update_status(self.database.pool(), scan_record_id, "completed").await?;
                result
            }
            _ = cancel_rx.recv() => {
                ScanOperations::update_status(self.database.pool(), scan_record_id, "cancelled").await?;
                Err(anyhow::anyhow!("Scan cancelled"))
            }
        }
    }

    async fn execute_quick_scan(
        &self,
        target: ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<ScanResult> {
        // Use masscan for fast discovery
        let results = self.masscan_scanner
            .fast_port_discovery(
                &target.ip.to_string(),
                100, // Top 100 ports
                Some(progress_tx.clone())
            ).await?;

        if let Some(result) = results.first() {
            self.store_scan_result(result).await?;
            Ok(result.clone())
        } else {
            // No ports found, still create empty result
            Ok(ScanResult {
                id: Uuid::new_v4(),
                target_id: target.id,
                timestamp: Utc::now(),
                status: ScanStatus::Completed,
                open_ports: Vec::new(),
                os_detection: None,
                vulnerabilities: Vec::new(),
            })
        }
    }

    async fn execute_comprehensive_scan(
        &self,
        target: ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<ScanResult> {
        // First phase: Fast port discovery with masscan
        let _ = progress_tx.send(ScanProgress {
            percent: 10.0,
            message: "Starting port discovery...".to_string(),
            eta: None,
        }).await;

        let discovery_results = self.masscan_scanner
            .scan_range(&[target.ip], &[], Some(progress_tx.clone()))
            .await?;

        // Second phase: Detailed nmap scan on discovered ports
        let _ = progress_tx.send(ScanProgress {
            percent: 50.0,
            message: "Performing detailed analysis...".to_string(),
            eta: None,
        }).await;

        let detailed_result = self.nmap_scanner
            .scan_target(&target, Some(progress_tx))
            .await?;

        self.store_scan_result(&detailed_result).await?;
        Ok(detailed_result)
    }

    async fn execute_stealth_scan(
        &self,
        target: ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<ScanResult> {
        // Rate limited stealth scan
        while !self.rate_limiter.acquire().await {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        let result = self.nmap_scanner
            .scan_target(&target, Some(progress_tx))
            .await?;

        self.store_scan_result(&result).await?;
        Ok(result)
    }

    async fn execute_custom_scan(
        &self,
        target: ScanTarget,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<ScanResult> {
        let result = self.nmap_scanner
            .scan_target(&target, Some(progress_tx))
            .await?;

        self.store_scan_result(&result).await?;
        Ok(result)
    }

    async fn store_scan_result(&self, result: &ScanResult) -> Result<()> {
        // Store/update host
        let host = match HostOperations::find_by_ip(self.database.pool(), result.target_id.into()).await? {
            Some(existing) => existing,
            None => {
                HostOperations::create(
                    self.database.pool(),
                    result.target_id.into(), // This should be the IP
                    None
                ).await?
            }
        };

        // Store ports
        for port in &result.open_ports {
            let port_record = PortOperations::create(
                self.database.pool(),
                &host.id,
                port.number,
                &port.protocol,
                &port.state,
            ).await?;

            if let (Some(service), Some(version)) = (&port.service, &port.version) {
                PortOperations::update_service_info(
                    self.database.pool(),
                    &port_record.id,
                    Some(service),
                    Some(version),
                    port.banner.as_deref(),
                ).await?;
            }
        }

        // Store OS detection
        if let Some(os) = &result.os_detection {
            HostOperations::update_os_info(
                self.database.pool(),
                &host.id,
                &os.name,
                &os.family,
                os.accuracy,
            ).await?;
        }

        // Store vulnerabilities
        for vuln in &result.vulnerabilities {
            VulnerabilityOperations::create(
                self.database.pool(),
                &host.id,
                None, // Link to specific port if needed
                &vuln.name,
                &format!("{:?}", vuln.severity),
                &vuln.description,
                vuln.cvss_score,
            ).await?;
        }

        Ok(())
    }

    pub async fn scan_network_range(
        &self,
        cidr: &str,
        excludes: &[String],
        scan_type: ScanType,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> Result<Vec<Uuid>> {
        InputValidator::validate_cidr(cidr)?;
        
        let targets = NetworkUtils::generate_target_list(&[cidr.to_string()], excludes)?;
        let mut scan_ids = Vec::new();

        let total_targets = targets.len();
        for (index, ip) in targets.into_iter().enumerate() {
            let target = ScanTarget {
                id: Uuid::new_v4(),
                ip,
                hostname: None,
                ports: vec![],
                scan_type: scan_type.clone(),
            };

            let (individual_progress_tx, mut individual_progress_rx) = mpsc::channel(100);
            let network_progress_tx = progress_tx.clone();
            
            // Forward individual progress as network progress
            tokio::spawn(async move {
                while let Some(individual_progress) = individual_progress_rx.recv().await {
                    let network_progress = ScanProgress {
                        percent: (index as f32 / total_targets as f32) * 100.0,
                        message: format!("Scanning {} ({}/{}): {}", 
                            ip, index + 1, total_targets, individual_progress.message),
                        eta: individual_progress.eta,
                    };
                    let _ = network_progress_tx.send(network_progress).await;
                }
            });

            let scan_id = self.start_scan(target, individual_progress_tx).await?;
            scan_ids.push(scan_id);
        }

        Ok(scan_ids)
    }

    async fn update_scan_status(&self, scan_id: &Uuid, status: ScanStatus) {
        let mut scans = self.active_scans.write().await;
        if let Some(handle) = scans.get_mut(scan_id) {
            handle.status = status;
        }
    }

    async fn handle_scan_completion(&self, scan_id: Uuid, result: Result<ScanResult>) {
        match result {
            Ok(scan_result) => {
                let _ = self.results_tx.send(scan_result).await;
                self.update_scan_status(&scan_id, ScanStatus::Completed).await;
            }
            Err(e) => {
                eprintln!("Scan {} failed: {}", scan_id, e);
                self.update_scan_status(&scan_id, ScanStatus::Failed { 
                    error: e.to_string() 
                }).await;
            }
        }

        // Remove from active scans
        let mut scans = self.active_scans.write().await;
        scans.remove(&scan_id);
    }

    pub async fn cancel_scan(&self, scan_id: Uuid) -> Result<()> {
        let mut scans = self.active_scans.write().await;
        
        if let Some(handle) = scans.remove(&scan_id) {
            if let Some(cancel_tx) = handle.cancel_tx {
                let _ = cancel_tx.send(()).await;
            }
        }
        
        Ok(())
    }

    pub async fn get_active_scans(&self) -> Vec<(Uuid, ScanStatus)> {
        let scans = self.active_scans.read().await;
        scans.iter()
            .map(|(id, handle)| (*id, handle.status.clone()))
            .collect()
    }

    pub async fn get_scan_statistics(&self) -> ScanStatistics {
        let scans = self.active_scans.read().await;
        let total_active = scans.len();
        let running = scans.values().filter(|h| matches!(h.status, ScanStatus::Running)).count();
        let queued = scans.values().filter(|h| matches!(h.status, ScanStatus::Queued)).count();

        ScanStatistics {
            total_active,
            running,
            queued,
        }
    }
}

// Make ScanCoordinator cloneable for async tasks
impl Clone for ScanCoordinator {
    fn clone(&self) -> Self {
        Self {
            active_scans: self.active_scans.clone(),
            nmap_scanner: NmapScanner::new(5),
            masscan_scanner: MasscanScanner::new(3, 10000),
            database: self.database.clone(),
            process_manager: ProcessManager::new(300),
            rate_limiter: self.rate_limiter.clone(),
            results_tx: self.results_tx.clone(),
            scan_semaphore: self.scan_semaphore.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_active: usize,
    pub running: usize,
    pub queued: usize,
}

// Helper trait for boxing futures
use futures::future::{BoxFuture, FutureExt};

trait BoxedFuture<T> {
    fn boxed(self) -> BoxFuture<'static, T>;
}

impl<F, T> BoxedFuture<T> for F
where
    F: std::future::Future<Output = T> + Send + 'static,
{
    fn boxed(self) -> BoxFuture<'static, T> {
        Box::pin(self)
    }
}