// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.
// LEGION (https://gotham-security.com)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::Arc;

use tauri::State;
use serde::{Deserialize, Serialize};

use crate::analysis::{AnalysisEngine, AnalysisResult};
use crate::database::{Db, VulnerabilityRecord};
use crate::analysis::vulnerability::VulnerabilityEngine;

/// Run analysis for a specific host
#[tauri::command]
pub async fn analyze_host(
    engine: State<'_, AnalysisEngine>,
    host_ip: String,
) -> Result<AnalysisResult, String> {
    engine
        .analyze_host(&host_ip)
        .await
        .map_err(|e| e.to_string())
}

/// Run full network analysis
#[tauri::command]
pub async fn analyze_network(
    engine: State<'_, AnalysisEngine>,
) -> Result<AnalysisResult, String> {
    engine.analyze_network().await.map_err(|e| e.to_string())
}

/// Get currently running analyses
#[tauri::command]
pub async fn get_active_analyses(
    engine: State<'_, AnalysisEngine>,
) -> Result<Vec<String>, String> {
    Ok(engine.get_active_analyses().await)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub host_ip: String,
    pub name: String,
    pub severity: String,
    pub description: String,
    pub cve_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub discovered_at: String,
    pub last_seen: String,
}

impl From<VulnerabilityRecord> for VulnerabilityInfo {
    fn from(record: VulnerabilityRecord) -> Self {
        Self {
            id: record.id,
            host_ip: record.host_ip,
            name: record.name,
            severity: record.severity,
            description: record.description,
            cve_id: record.cve_id,
            cvss_score: record.cvss_score,
            discovered_at: record.discovered_at,
            last_seen: record.last_seen,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityAnalysisRequest {
    pub host_ip: String,
    pub force_rescan: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityAnalysisResponse {
    pub host_ip: String,
    pub vulnerabilities_found: usize,
    pub analysis_time_ms: u64,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
}

/// Get all vulnerabilities for a specific host
#[tauri::command]
pub async fn get_host_vulnerabilities(
    host_ip: String,
    db: State<'_, Arc<Db>>,
) -> Result<Vec<VulnerabilityInfo>, String> {
    let vulnerabilities = db
        .get_vulnerabilities_by_host_ip(&host_ip)
        .await
        .map_err(|e| format!("Failed to get vulnerabilities for host {}: {}", host_ip, e))?;
    
    let vuln_infos: Vec<VulnerabilityInfo> = vulnerabilities
        .into_iter()
        .map(VulnerabilityInfo::from)
        .collect();
    
    Ok(vuln_infos)
}

/// Get all vulnerabilities across all hosts
#[tauri::command]
pub async fn get_all_vulnerabilities(
    db: State<'_, Arc<Db>>,
) -> Result<Vec<VulnerabilityInfo>, String> {
    let vulnerabilities = db
        .get_all_vulnerabilities()
        .await
        .map_err(|e| format!("Failed to get all vulnerabilities: {}", e))?;
    
    let vuln_infos: Vec<VulnerabilityInfo> = vulnerabilities
        .into_iter()
        .map(VulnerabilityInfo::from)
        .collect();
    
    Ok(vuln_infos)
}

/// Run vulnerability analysis on a specific host
#[tauri::command]
pub async fn analyze_host_vulnerabilities(
    request: VulnerabilityAnalysisRequest,
    db: State<'_, Arc<Db>>,
) -> Result<VulnerabilityAnalysisResponse, String> {
    let start_time = std::time::Instant::now();
    
    log::info!("Starting vulnerability analysis for host: {}", request.host_ip);
    
    let vulnerability_engine = VulnerabilityEngine::new(db.inner().clone());
    
    let vulnerabilities = vulnerability_engine
        .analyze_host(&request.host_ip)
        .await
        .map_err(|e| format!("Vulnerability analysis failed for host {}: {}", request.host_ip, e))?;
    
    let analysis_time = start_time.elapsed();
    
    let vuln_infos: Vec<VulnerabilityInfo> = vulnerabilities
        .into_iter()
        .map(|v| VulnerabilityInfo {
            id: v.finding.id,
            host_ip: v.finding.host,
            name: v.finding.title,
            severity: format!("{:?}", v.finding.severity),
            description: v.finding.description,
            cve_id: v.cve_id,
            cvss_score: v.cvss_score,
            discovered_at: v.finding.created_at.to_rfc3339(),
            last_seen: v.finding.created_at.to_rfc3339(),
        })
        .collect();
    
    log::info!(
        "Vulnerability analysis completed for host {} in {}ms: {} vulnerabilities found",
        request.host_ip,
        analysis_time.as_millis(),
        vuln_infos.len()
    );
    
    Ok(VulnerabilityAnalysisResponse {
        host_ip: request.host_ip,
        vulnerabilities_found: vuln_infos.len(),
        analysis_time_ms: analysis_time.as_millis() as u64,
        vulnerabilities: vuln_infos,
    })
}

/// Get vulnerability statistics
#[tauri::command]
pub async fn get_vulnerability_stats(
    db: State<'_, Arc<Db>>,
) -> Result<VulnerabilityStats, String> {
    let vulnerabilities = db
        .get_all_vulnerabilities()
        .await
        .map_err(|e| format!("Failed to get vulnerabilities for stats: {}", e))?;
    
    let mut stats = VulnerabilityStats::default();
    
    for vuln in &vulnerabilities {
        stats.total += 1;
        
        match vuln.severity.to_lowercase().as_str() {
            "critical" => stats.critical += 1,
            "high" => stats.high += 1,
            "medium" => stats.medium += 1,
            "low" => stats.low += 1,
            _ => stats.unknown += 1,
        }
        
        if vuln.cve_id.is_some() {
            stats.with_cve += 1;
        }
        
        if let Some(score) = vuln.cvss_score {
            if score > stats.highest_cvss_score {
                stats.highest_cvss_score = score;
            }
        }
    }
    
    // Get unique affected hosts
    let unique_hosts: std::collections::HashSet<String> = vulnerabilities
        .iter()
        .map(|v| v.host_ip.clone())
        .collect();
    stats.affected_hosts = unique_hosts.len();
    
    Ok(stats)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
    pub with_cve: usize,
    pub affected_hosts: usize,
    pub highest_cvss_score: f32,
}

impl Default for VulnerabilityStats {
    fn default() -> Self {
        Self {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
            with_cve: 0,
            affected_hosts: 0,
            highest_cvss_score: 0.0,
        }
    }
}
