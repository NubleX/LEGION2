// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use crate::database::Db;
use crate::network::network::parse_target_specification;
use crate::shared::shared::Host;
use crate::shared::scan_types::OSDetection;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tauri::State;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub number: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub cve_count: u32,
    pub enrichment_status: String, // "none", "pending", "completed", "error"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub description: Option<String>,
}

/// Return only the IPs from the database that fall within the given target specification (CIDR, range, etc.)
/// Used by massmap to build the nmap follow-up plan targeting only masscan-discovered hosts.
#[tauri::command]
pub async fn get_hosts_in_range(
    targets: String,
    db: State<'_, Arc<Db>>,
) -> Result<Vec<String>, String> {
    let target_ips: HashSet<IpAddr> = parse_target_specification(&targets)
        .map_err(|e| format!("Failed to parse target specification: {}", e))?
        .into_iter()
        .collect();

    let all_hosts = db.inner().get_all_hosts().await.map_err(|e| e.to_string())?;

    let in_range: Vec<String> = all_hosts
        .into_iter()
        .filter_map(|h| {
            h.ip.parse::<IpAddr>()
                .ok()
                .filter(|ip| target_ips.contains(ip))
                .map(|_| h.ip)
        })
        .collect();

    Ok(in_range)
}

#[tauri::command]
pub async fn get_all_hosts(
    db: State<'_, Arc<Db>>,
    _status_filter: Option<String>,
) -> Result<Vec<Host>, String> {
    db.inner().get_all_hosts().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_host_details(
    host_id: String,
    db: State<'_, Arc<Db>>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let ports = db
        .inner()
        .get_host_ports(&host_id)
        .await
        .map_err(|e| e.to_string())?;
    let vulns = db
        .inner()
        .get_host_vulnerabilities(&host_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok((ports, vulns))
}

#[tauri::command]
pub async fn delete_host(host_id: String, db: State<'_, Arc<Db>>) -> Result<(), String> {
    db.inner()
        .delete_host(&host_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_all_hosts(db: State<'_, Arc<Db>>) -> Result<u64, String> {
    db.inner()
        .clear_all_hosts()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn batch_import_hosts(hosts: Vec<String>, db: State<'_, Arc<Db>>) -> Result<(), String> {
    for ip in hosts {
        if let Err(e) = db
            .inner()
            .upsert_host(&ip, None, None, None, None, None, None, None)
            .await
        {
            return Err(format!("Failed to import host {}: {}", ip, e));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn update_host_tags(
    host_id: String,
    tags: Vec<String>,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    db.inner()
        .update_host_tags(&host_id, &tags)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_host_os_detection(
    host_ip: String,
    os_detection: OSDetection,
    db: State<'_, Arc<Db>>,
) -> Result<(), String> {
    db.inner()
        .update_host_os(
            &host_ip,
            Some(&os_detection.name),
            Some(&os_detection.family),
            Some(os_detection.accuracy),
        )
        .await
        .map_err(|e| format!("Failed to update OS detection for {}: {}", host_ip, e))
}

#[tauri::command]
pub async fn get_host_by_ip(db: State<'_, Arc<Db>>, ip: String) -> Result<Host, String> {
    let hosts = db
        .inner()
        .get_all_hosts()
        .await
        .map_err(|e| e.to_string())?;
    hosts
        .into_iter()
        .find(|h| h.ip == ip)
        .ok_or_else(|| "Host not found".to_string())
}

#[tauri::command]
pub async fn get_host_ports_detailed(
    host_ip: String,
    db: State<'_, Arc<Db>>,
) -> Result<Vec<PortInfo>, String> {
    log::info!("Getting ports for host IP: {}", host_ip);

    // Ensure the host exists in the database. If it was just created during a scan,
    // this will insert it so we can still query its ports without errors.
    if let Err(e) = db
        .inner()
        .upsert_host(&host_ip, None, None, None, None, None, None, None)
        .await
    {
        log::warn!("Failed to upsert host {}: {}", host_ip, e);
    }

    // Ports are keyed by host IP, so we can query them directly.
    let ports = db
        .inner()
        .get_host_ports_detailed(&host_ip)
        .await
        .map_err(|e| e.to_string())?;
    log::info!("Found {} ports for host IP: {}", ports.len(), host_ip);

    Ok(ports)
}

#[tauri::command]
pub async fn get_host_services(
    host_ip: String,
    db: State<'_, Arc<Db>>,
) -> Result<Vec<ServiceInfo>, String> {
    log::info!("Getting services for host IP: {}", host_ip);

    // Ensure the host exists
    if let Err(e) = db
        .inner()
        .upsert_host(&host_ip, None, None, None, None, None, None, None)
        .await
    {
        log::warn!("Failed to upsert host {}: {}", host_ip, e);
    }

    let services = db
        .inner()
        .get_host_services_detailed(&host_ip)
        .await
        .map_err(|e| e.to_string())?;
    log::info!("Found {} services for host IP: {}", services.len(), host_ip);

    Ok(services)
}

#[tauri::command]
pub async fn get_service_cves(
    host_ip: String,
    port: u16,
    service_name: Option<String>,
    db: State<'_, Arc<Db>>,
) -> Result<Vec<CveInfo>, String> {
    log::info!("Getting CVEs for service {}:{} on host {}", port, service_name.as_deref().unwrap_or("unknown"), host_ip);

    let cves = db
        .inner()
        .get_service_cves(&host_ip, port, service_name.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    log::info!("Found {} CVEs for service {}:{}", cves.len(), port, service_name.as_deref().unwrap_or("unknown"));

    Ok(cves)
}

#[tauri::command]
pub async fn enrich_service_osint(
    host_ip: String,
    port: u16,
    service_name: Option<String>,
    _version: Option<String>,
    _db: State<'_, Arc<Db>>,
) -> Result<String, String> {
    // Placeholder for OSINT enrichment
    // Will be implemented when OSINT module is ready
    log::info!("OSINT enrichment requested for {}:{} ({})", host_ip, port, service_name.as_deref().unwrap_or("unknown"));
    Ok("OSINT enrichment not yet implemented".to_string())
}
