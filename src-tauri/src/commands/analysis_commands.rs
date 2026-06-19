// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

use crate::analysis::vulnerability::VulnerabilityEngine;
use crate::analysis::{AnalysisEngine, AnalysisResult};
use crate::database::{Db, VulnerabilityRecord};
use crate::session_state::{self, SessionAnalyticsInfo};
use crate::shared::parser::parse_nmap_content;
use crate::shared::service::{Service, ServiceAnalyzer, ServiceStatistics};

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
pub async fn analyze_network(engine: State<'_, AnalysisEngine>) -> Result<AnalysisResult, String> {
    engine
        .analyze_network(None)
        .await
        .map_err(|e| e.to_string())
}

/// Get currently running analyses
#[tauri::command]
pub async fn get_active_analyses(engine: State<'_, AnalysisEngine>) -> Result<Vec<String>, String> {
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

    log::info!(
        "Starting vulnerability analysis for host: {}",
        request.host_ip
    );

    let vulnerability_engine = VulnerabilityEngine::new(db.inner().clone());

    let vulnerabilities = vulnerability_engine
        .analyze_host(&request.host_ip)
        .await
        .map_err(|e| {
            format!(
                "Vulnerability analysis failed for host {}: {}",
                request.host_ip, e
            )
        })?;

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
pub async fn get_vulnerability_stats(db: State<'_, Arc<Db>>) -> Result<VulnerabilityStats, String> {
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
    let unique_hosts: std::collections::HashSet<String> =
        vulnerabilities.iter().map(|v| v.host_ip.clone()).collect();
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatisticsInfo {
    pub total_services: usize,
    pub vulnerable_services: usize,
    pub web_services: usize,
    pub database_services: usize,
    pub average_risk_score: f64,
}

impl From<ServiceStatistics> for ServiceStatisticsInfo {
    fn from(stats: ServiceStatistics) -> Self {
        Self {
            total_services: stats.total_services,
            vulnerable_services: stats.vulnerable_services,
            web_services: stats.web_services,
            database_services: stats.database_services,
            average_risk_score: stats.average_risk_score,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub hosts_imported: usize,
    pub session_summary: String,
}

/// Service risk statistics for a host using ServiceAnalyzer
#[tauri::command]
pub async fn get_service_statistics(
    host_ip: String,
    db: State<'_, Arc<Db>>,
) -> Result<ServiceStatisticsInfo, String> {
    let ports = db
        .inner()
        .get_host_ports_detailed(&host_ip)
        .await
        .map_err(|e| e.to_string())?;

    let services: Vec<Service> = ports
        .into_iter()
        .filter_map(|port| {
            if port.service.is_none() && port.version.is_none() && port.banner.is_none() {
                return None;
            }
            let mut service = Service::new();
            service.name = port.service.clone().unwrap_or_default();
            service.version = port.version.clone().unwrap_or_default();
            service.extrainfo = port.banner.clone().unwrap_or_default();
            service.proto = port.protocol;
            Some(service)
        })
        .collect();

    Ok(ServiceAnalyzer::get_service_statistics(&services).into())
}

/// Parse nmap XML and import discovered hosts into the database
#[tauri::command]
pub async fn import_nmap_xml(
    xml_content: String,
    db: State<'_, Arc<Db>>,
) -> Result<ImportResult, String> {
    let parser = parse_nmap_content(&xml_content)
        .map_err(|e| format!("Failed to parse nmap XML: {}", e))?;

    let session_summary = parser.get_session().scan_summary();
    let mut hosts_imported = 0usize;

    for host in parser.get_all_hosts(Some("up")) {
        let ip = host.get_ip();
        if ip.is_empty() {
            continue;
        }

        db.inner()
            .upsert_host(
                ip,
                if host.hostname.is_empty() {
                    None
                } else {
                    Some(host.hostname.as_str())
                },
                Some(host.status.as_str()),
                if host.macaddr.is_empty() {
                    None
                } else {
                    Some(host.macaddr.as_str())
                },
                if host.vendor.is_empty() {
                    None
                } else {
                    Some(host.vendor.as_str())
                },
                None,
                None,
                None,
            )
            .await
            .map_err(|e| format!("Failed to import host {}: {}", ip, e))?;
        hosts_imported += 1;
    }

    session_state::record_from_xml(&xml_content)
        .map_err(|e| format!("Failed to parse session metadata: {}", e))?;

    Ok(ImportResult {
        hosts_imported,
        session_summary,
    })
}

/// Parse nmap XML and return session analytics
#[tauri::command]
pub async fn parse_scan_session(xml_content: String) -> Result<SessionAnalyticsInfo, String> {
    session_state::record_from_xml(&xml_content)
        .map_err(|e| format!("Failed to parse scan session: {}", e))
}

/// Return the most recently recorded scan session analytics
#[tauri::command]
pub async fn get_latest_session_analytics() -> Result<Option<SessionAnalyticsInfo>, String> {
    Ok(session_state::latest_analytics())
}
