// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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

use crate::database::{Database, models::*};
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;

pub struct HostOperations;

impl HostOperations {
    pub async fn upsert(db: &Database, ip: &str, hostname: Option<&str>) -> Result<Host> {
        let mut hosts = db.hosts().write().await;
        
        // Check if host already exists
        if let Some(existing) = hosts.values_mut().find(|h| h.ip == ip) {
            // Update existing host
            if hostname.is_some() && existing.hostname.is_none() {
                existing.hostname = hostname.map(|s| s.to_string());
            }
            existing.updated_at = Utc::now();
            return Ok(existing.clone());
        }
        
        // Create new host
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let host = Host {
            id: id.clone(),
            ip: ip.to_string(),
            hostname: hostname.map(|s| s.to_string()),
            mac_address: None,
            vendor: None,
            os_name: None,
            os_family: None,
            os_accuracy: None,
            status: "up".to_string(),
            created_at: now,
            updated_at: now,
        };

        hosts.insert(id, host.clone());
        Ok(host)
    }

    pub async fn update_os(
        db: &Database,
        host_id: &str,
        os_name: &str,
        vendor: &str,
        accuracy: f32,
    ) -> Result<()> {
        let mut hosts = db.hosts().write().await;
        
        if let Some(host) = hosts.get_mut(host_id) {
            host.os_name = Some(os_name.to_string());
            host.vendor = Some(vendor.to_string());
            host.os_accuracy = Some(accuracy);
            host.updated_at = Utc::now();
        }
        
        Ok(())
    }

    pub async fn list_all(db: &Database) -> Result<Vec<Host>> {
        let hosts = db.hosts().read().await;
        let mut host_list: Vec<Host> = hosts.values().cloned().collect();
        host_list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(host_list)
    }

    pub async fn get_with_ports(db: &Database, host_id: &str) -> Result<(Host, Vec<Port>)> {
        let hosts = db.hosts().read().await;
        let host = hosts.get(host_id)
            .ok_or_else(|| anyhow::anyhow!("Host not found"))?
            .clone();

        let ports_map = db.ports().read().await;
        let mut ports: Vec<Port> = ports_map.values()
            .filter(|p| p.host_id == host_id)
            .cloned()
            .collect();
        ports.sort_by_key(|p| p.number);

        Ok((host, ports))
    }
}

pub struct PortOperations;

impl PortOperations {
    pub async fn create(
        db: &Database,
        host_id: &str,
        number: i32,
        protocol: &str,
        state: &str,
        service: Option<&str>,
        version: Option<&str>,
    ) -> Result<Port> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let port = Port {
            id: id.clone(),
            host_id: host_id.to_string(),
            number,
            protocol: protocol.to_string(),
            state: state.to_string(),
            service: service.map(|s| s.to_string()),
            version: version.map(|s| s.to_string()),
            banner: None,
            created_at: now,
        };

        let mut ports = db.ports().write().await;
        
        // Check if port already exists for this host
        let existing_key = ports.iter()
            .find(|(_, p)| p.host_id == host_id && p.number == number && p.protocol == protocol)
            .map(|(k, _)| k.clone());
            
        if let Some(key) = existing_key {
            // Update existing port
            if let Some(existing) = ports.get_mut(&key) {
                existing.state = state.to_string();
                existing.service = service.map(|s| s.to_string());
                existing.version = version.map(|s| s.to_string());
                return Ok(existing.clone());
            }
        }
        
        // Insert new port
        ports.insert(id, port.clone());
        Ok(port)
    }

    pub async fn find_by_host(db: &Database, host_id: &str) -> Result<Vec<Port>> {
        let ports = db.ports().read().await;
        let mut port_list: Vec<Port> = ports.values()
            .filter(|p| p.host_id == host_id)
            .cloned()
            .collect();
        port_list.sort_by_key(|p| p.number);
        Ok(port_list)
    }
}

pub struct VulnerabilityOperations;

impl VulnerabilityOperations {
    pub async fn create(
        db: &Database,
        host_id: &str,
        port_id: Option<&str>,
        vuln: &crate::scanning::Vulnerability,
    ) -> Result<Vulnerability> {
        let id = Uuid::new_v4().to_string();
        
        let references_json = serde_json::to_string(&vuln.references)
            .unwrap_or_else(|_| "[]".to_string());
        
        let vulnerability = Vulnerability {
            id: id.clone(),
            host_id: host_id.to_string(),
            port_id: port_id.map(|s| s.to_string()),
            name: vuln.name.clone(),
            severity: vuln.severity.to_string(),
            description: vuln.description.clone(),
            cvss_score: vuln.cvss_score,
            references: Some(references_json),
            discovered_at: Utc::now(),
        };

        let mut vulnerabilities = db.vulnerabilities().write().await;
        vulnerabilities.insert(id, vulnerability.clone());

        Ok(vulnerability)
    }

    pub async fn find_by_host(db: &Database, host_id: &str) -> Result<Vec<Vulnerability>> {
        let vulnerabilities = db.vulnerabilities().read().await;
        let mut vulns: Vec<Vulnerability> = vulnerabilities.values()
            .filter(|v| v.host_id == host_id)
            .cloned()
            .collect();
        vulns.sort_by(|a, b| b.discovered_at.cmp(&a.discovered_at));
        Ok(vulns)
    }

    pub async fn find_high_severity(db: &Database) -> Result<Vec<Vulnerability>> {
        let vulnerabilities = db.vulnerabilities().read().await;
        let mut vulns: Vec<Vulnerability> = vulnerabilities.values()
            .filter(|v| v.severity == "high" || v.severity == "critical")
            .cloned()
            .collect();
        vulns.sort_by(|a, b| b.discovered_at.cmp(&a.discovered_at));
        Ok(vulns)
    }

    pub async fn list_all(db: &Database) -> Result<Vec<Vulnerability>> {
        let vulnerabilities = db.vulnerabilities().read().await;
        let mut vulns: Vec<Vulnerability> = vulnerabilities.values().cloned().collect();
        vulns.sort_by(|a, b| b.discovered_at.cmp(&a.discovered_at));
        Ok(vulns)
    }
}

pub struct ProjectOperations;

impl ProjectOperations {
    pub async fn create(db: &Database, name: &str, description: Option<&str>) -> Result<Project> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let project = Project {
            id: id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            created_at: now,
            updated_at: now,
        };

        let mut projects = db.projects().write().await;
        projects.insert(id, project.clone());

        Ok(project)
    }

    pub async fn list_all(db: &Database) -> Result<Vec<Project>> {
        let projects = db.projects().read().await;
        let mut project_list: Vec<Project> = projects.values().cloned().collect();
        project_list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(project_list)
    }
}