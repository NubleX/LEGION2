use crate::database::{Database, models::*};
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;
use std::net::IpAddr;

pub struct HostOperations;

impl HostOperations {
    pub async fn create(db: &Database, ip: IpAddr, hostname: Option<&str>) -> Result<Host> {
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
            status: "unknown".to_string(),
            created_at: now,
            updated_at: now,
        };

        let mut hosts = db.hosts().write().await;
        hosts.insert(id, host.clone());

        Ok(host)
    }

    pub async fn find_by_ip(db: &Database, ip: IpAddr) -> Result<Option<Host>> {
        let hosts = db.hosts().read().await;
        let host = hosts.values().find(|h| h.ip == ip.to_string()).cloned();
        Ok(host)
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
        let ports: Vec<Port> = ports_map.values()
            .filter(|p| p.host_id == host_id)
            .cloned()
            .collect();

        Ok((host, ports))
    }
}

pub struct PortOperations;

impl PortOperations {
    pub async fn create(
        db: &Database,
        host_id: &str,
        number: u16,
        protocol: &str,
        state: &str,
    ) -> Result<Port> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let port = Port {
            id: id.clone(),
            host_id: host_id.to_string(),
            number: number as i32,
            protocol: protocol.to_string(),
            state: state.to_string(),
            service: None,
            version: None,
            banner: None,
            created_at: now,
        };

        let mut ports = db.ports().write().await;
        ports.insert(id, port.clone());

        Ok(port)
    }
}

pub struct VulnerabilityOperations;

impl VulnerabilityOperations {
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