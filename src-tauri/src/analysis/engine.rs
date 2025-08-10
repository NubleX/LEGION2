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

use std::sync::Arc;
use anyhow::Result;
use tokio::sync::RwLock;
use tauri::{AppHandle, Emitter};

use crate::db::Db;
use crate::analysis::types::{AnalysisResult, Finding, Vulnerability, AttackPath, NetworkTopology};
use crate::analysis::vulnerability::VulnerabilityEngine;
use crate::analysis::correlation::CorrelationEngine;

/// Central analysis engine that coordinates all analysis activities
pub struct AnalysisEngine {
    db: Arc<Db>,
    app_handle: Option<AppHandle>,
    vulnerability_engine: VulnerabilityEngine,
    correlation_engine: CorrelationEngine,
    active_analyses: Arc<RwLock<Vec<String>>>, // Track running analysis IDs
}

impl AnalysisEngine {
    /// Create a new analysis engine
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db: db.clone(),
            app_handle: None,
            vulnerability_engine: VulnerabilityEngine::new(db.clone()),
            correlation_engine: CorrelationEngine::new(db.clone()),
            active_analyses: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create engine with UI integration
    pub fn with_ui(db: Arc<Db>, app_handle: AppHandle) -> Self {
        Self {
            db: db.clone(),
            app_handle: Some(app_handle),
            vulnerability_engine: VulnerabilityEngine::new(db.clone()),
            correlation_engine: CorrelationEngine::new(db.clone()),
            active_analyses: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Trigger analysis for a specific host 
    pub async fn analyze_host(&self, host_ip: &str) -> Result<AnalysisResult> {
        let analysis_id = format!("host_analysis_{}", host_ip);
        
        // Add to active analyses
        self.active_analyses.write().await.push(analysis_id.clone());
        
        self.emit_event("analysis:started", &analysis_id).await;

        // Run vulnerability analysis
        let vulnerabilities = self.vulnerability_engine.analyze_host(host_ip).await?;
        
        // Run correlation analysis
        let findings = self.correlation_engine.correlate_host_findings(host_ip).await?;
        
        // Generate attack paths
        let attack_paths = self.correlation_engine.generate_attack_paths(host_ip).await?;
        
        // Build topology (simplified for now)
        let topology = self.build_host_topology(host_ip).await?;

        let result = AnalysisResult {
            findings,
            vulnerabilities,
            attack_paths,
            topology,
            summary: self.generate_summary(&findings, &vulnerabilities).await?,
            generated_at: chrono::Utc::now(),
        };

        // Remove from active analyses
        self.active_analyses.write().await.retain(|id| id != &analysis_id);
        
        self.emit_event("analysis:completed", &result).await;
        
        Ok(result)
    }

    /// Trigger analysis when new service is discovered
    pub async fn on_service_discovered(&self, host_ip: &str, port: u16, service: &str) -> Result<Vec<Finding>> {
        log::info!("Analyzing discovered service: {}:{} ({})", host_ip, port, service);
        
        // Quick vulnerability check for this specific service
        let vulnerabilities = self.vulnerability_engine.analyze_service(host_ip, port, service).await?;
        
        // Convert vulnerabilities to findings
        let findings: Vec<Finding> = vulnerabilities.into_iter().map(|v| v.finding).collect();
        
        // Emit findings immediately for real-time updates
        for finding in &findings {
            self.emit_event("analysis:finding", finding).await;
        }
        
        Ok(findings)
    }

    /// Trigger analysis when new host is discovered
    pub async fn on_host_discovered(&self, host_ip: &str) -> Result<Vec<Finding>> {
        log::info!("Analyzing discovered host: {}", host_ip);
        
        // Basic host analysis - OS detection, open ports correlation, etc.
        let findings = self.correlation_engine.analyze_new_host(host_ip).await?;
        
        // Emit findings
        for finding in &findings {
            self.emit_event("analysis:finding", finding).await;
        }
        
        Ok(findings)
    }

    /// Run full network analysis
    pub async fn analyze_network(&self) -> Result<AnalysisResult> {
        let analysis_id = "network_analysis".to_string();
        
        self.active_analyses.write().await.push(analysis_id.clone());
        self.emit_event("analysis:started", &analysis_id).await;

        // Get all findings and vulnerabilities
        let findings = self.correlation_engine.correlate_all_findings().await?;
        let vulnerabilities = self.vulnerability_engine.analyze_all_hosts().await?;
        
        // Generate comprehensive attack paths
        let attack_paths = self.correlation_engine.generate_network_attack_paths().await?;
        
        // Build full network topology
        let topology = self.build_network_topology().await?;

        let result = AnalysisResult {
            findings,
            vulnerabilities,
            attack_paths,
            topology,
            summary: self.generate_summary(&[], &[]).await?, // TODO: Implement proper summary
            generated_at: chrono::Utc::now(),
        };

        self.active_analyses.write().await.retain(|id| id != &analysis_id);
        self.emit_event("analysis:completed", &result).await;
        
        Ok(result)
    }

    /// Get current analysis status
    pub async fn get_active_analyses(&self) -> Vec<String> {
        self.active_analyses.read().await.clone()
    }

    // Private helper methods
    async fn build_host_topology(&self, _host_ip: &str) -> Result<NetworkTopology> {
        // TODO: Query database for host topology
        Ok(NetworkTopology {
            hosts: Vec::new(),
            connections: Vec::new(),
            subnets: Vec::new(),
        })
    }

    async fn build_network_topology(&self) -> Result<NetworkTopology> {
        // TODO: Query database for full network topology
        Ok(NetworkTopology {
            hosts: Vec::new(),
            connections: Vec::new(),
            subnets: Vec::new(),
        })
    }

    async fn generate_summary(&self, _findings: &[Finding], _vulnerabilities: &[Vulnerability]) -> Result<crate::analysis::types::AnalysisSummary> {
        // TODO: Generate proper analysis summary
        Ok(crate::analysis::types::AnalysisSummary {
            total_hosts: 0,
            total_services: 0,
            vulnerability_count_by_severity: std::collections::HashMap::new(),
            top_risks: Vec::new(),
            recommended_actions: Vec::new(),
        })
    }

    async fn emit_event<T: serde::Serialize>(&self, event: &str, payload: &T) {
        if let Some(app) = &self.app_handle {
            if let Err(e) = app.emit(event, payload) {
                log::error!("Failed to emit analysis event '{}': {}", event, e);
            }
        }
    }
}

// Analysis engine should be integrated with the sink system
impl AnalysisEngine {
    /// Called by DbSink when new data is stored
    pub async fn trigger_incremental_analysis(&self, observation_kind: &str, host_ip: &str, data: &serde_json::Value) -> Result<()> {
        match observation_kind {
            "host" => {
                let findings = self.on_host_discovered(host_ip).await?;
                log::info!("Generated {} findings for new host {}", findings.len(), host_ip);
            }
            "service" => {
                if let (Some(port), Some(service)) = (
                    data.get("port").and_then(|v| v.as_u64()),
                    data.get("service").and_then(|v| v.as_str())
                ) {
                    let findings = self.on_service_discovered(host_ip, port as u16, service).await?;
                    log::info!("Generated {} findings for service {}:{}", findings.len(), host_ip, port);
                }
            }
            _ => {
                log::debug!("No analysis trigger for observation kind: {}", observation_kind);
            }
        }
        
        Ok(())
    }
}