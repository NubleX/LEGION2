use super::models::*;
use sqlx::{SqlitePool, Row};
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;
use std::net::IpAddr;

pub struct HostOperations;

impl HostOperations {
    pub async fn create(pool: &SqlitePool, ip: IpAddr, hostname: Option<String>) -> Result<Host> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let host = sqlx::query_as!(
            Host,
            r#"
            INSERT INTO hosts (id, ip, hostname, status, created_at, updated_at)
            VALUES (?, ?, ?, 'unknown', ?, ?)
            RETURNING *
            "#,
            id,
            ip.to_string(),
            hostname,
            now,
            now
        )
        .fetch_one(pool)
        .await?;
        
        Ok(host)
    }

    pub async fn find_by_ip(pool: &SqlitePool, ip: IpAddr) -> Result<Option<Host>> {
        let host = sqlx::query_as!(
            Host,
            "SELECT * FROM hosts WHERE ip = ?",
            ip.to_string()
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(host)
    }

    pub async fn update_os_info(
        pool: &SqlitePool,
        host_id: &str,
        os_name: &str,
        os_family: &str,
        accuracy: f32,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE hosts 
            SET os_name = ?, os_family = ?, os_accuracy = ?, updated_at = ?
            WHERE id = ?
            "#,
            os_name,
            os_family,
            accuracy,
            Utc::now(),
            host_id
        )
        .execute(pool)
        .await?;
        
        Ok(())
    }

    pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Host>> {
        let hosts = sqlx::query_as!(Host, "SELECT * FROM hosts ORDER BY created_at DESC")
            .fetch_all(pool)
            .await?;
        
        Ok(hosts)
    }

    pub async fn get_with_ports(pool: &SqlitePool, host_id: &str) -> Result<(Host, Vec<Port>)> {
        let host = sqlx::query_as!(Host, "SELECT * FROM hosts WHERE id = ?", host_id)
            .fetch_one(pool)
            .await?;

        let ports = PortOperations::find_by_host(pool, host_id).await?;
        
        Ok((host, ports))
    }
}

pub struct PortOperations;

impl PortOperations {
    pub async fn create(
        pool: &SqlitePool,
        host_id: &str,
        number: u16,
        protocol: &str,
        state: &str,
    ) -> Result<Port> {
        let id = Uuid::new_v4().to_string();
        
        let port = sqlx::query_as!(
            Port,
            r#"
            INSERT INTO ports (id, host_id, number, protocol, state, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING *
            "#,
            id,
            host_id,
            number as i32,
            protocol,
            state,
            Utc::now()
        )
        .fetch_one(pool)
        .await?;
        
        Ok(port)
    }

    pub async fn update_service_info(
        pool: &SqlitePool,
        port_id: &str,
        service: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            "UPDATE ports SET service = ?, version = ?, banner = ? WHERE id = ?",
            service,
            version,
            banner,
            port_id
        )
        .execute(pool)
        .await?;
        
        Ok(())
    }

    pub async fn find_by_host(pool: &SqlitePool, host_id: &str) -> Result<Vec<Port>> {
        let ports = sqlx::query_as!(
            Port,
            "SELECT * FROM ports WHERE host_id = ? ORDER BY number",
            host_id
        )
        .fetch_all(pool)
        .await?;
        
        Ok(ports)
    }

    pub async fn find_open_ports(pool: &SqlitePool, host_id: &str) -> Result<Vec<Port>> {
        let ports = sqlx::query_as!(
            Port,
            "SELECT * FROM ports WHERE host_id = ? AND state = 'open' ORDER BY number",
            host_id
        )
        .fetch_all(pool)
        .await?;
        
        Ok(ports)
    }
}

pub struct ScanOperations;

impl ScanOperations {
    pub async fn create(
        pool: &SqlitePool,
        name: &str,
        targets: &[IpAddr],
        scan_type: &str,
    ) -> Result<Scan> {
        let id = Uuid::new_v4().to_string();
        let targets_json = serde_json::to_string(targets)?;
        
        let scan = sqlx::query_as!(
            Scan,
            r#"
            INSERT INTO scans (id, name, targets, scan_type, status, progress, start_time, created_at)
            VALUES (?, ?, ?, ?, 'queued', 0.0, ?, ?)
            RETURNING *
            "#,
            id,
            name,
            targets_json,
            scan_type,
            Utc::now(),
            Utc::now()
        )
        .fetch_one(pool)
        .await?;
        
        Ok(scan)
    }

    pub async fn update_progress(pool: &SqlitePool, scan_id: &str, progress: f32) -> Result<()> {
        sqlx::query!(
            "UPDATE scans SET progress = ? WHERE id = ?",
            progress,
            scan_id
        )
        .execute(pool)
        .await?;
        
        Ok(())
    }

    pub async fn update_status(pool: &SqlitePool, scan_id: &str, status: &str) -> Result<()> {
        let end_time = if status == "completed" || status == "failed" {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query!(
            "UPDATE scans SET status = ?, end_time = ? WHERE id = ?",
            status,
            end_time,
            scan_id
        )
        .execute(pool)
        .await?;
        
        Ok(())
    }

    pub async fn list_recent(pool: &SqlitePool, limit: i32) -> Result<Vec<Scan>> {
        let scans = sqlx::query_as!(
            Scan,
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
            limit
        )
        .fetch_all(pool)
        .await?;
        
        Ok(scans)
    }
}

pub struct VulnerabilityOperations;

impl VulnerabilityOperations {
    pub async fn create(
        pool: &SqlitePool,
        host_id: &str,
        port_id: Option<&str>,
        name: &str,
        severity: &str,
        description: &str,
        cvss_score: Option<f32>,
    ) -> Result<Vulnerability> {
        let id = Uuid::new_v4().to_string();
        
        let vuln = sqlx::query_as!(
            Vulnerability,
            r#"
            INSERT INTO vulnerabilities (id, host_id, port_id, name, severity, description, cvss_score, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING *
            "#,
            id,
            host_id,
            port_id,
            name,
            severity,
            description,
            cvss_score,
            Utc::now()
        )
        .fetch_one(pool)
        .await?;
        
        Ok(vuln)
    }

    pub async fn find_by_host(pool: &SqlitePool, host_id: &str) -> Result<Vec<Vulnerability>> {
        let vulns = sqlx::query_as!(
            Vulnerability,
            "SELECT * FROM vulnerabilities WHERE host_id = ? ORDER BY discovered_at DESC",
            host_id
        )
        .fetch_all(pool)
        .await?;
        
        Ok(vulns)
    }

    pub async fn find_high_severity(pool: &SqlitePool) -> Result<Vec<Vulnerability>> {
        let vulns = sqlx::query_as!(
            Vulnerability,
            "SELECT * FROM vulnerabilities WHERE severity IN ('high', 'critical') ORDER BY discovered_at DESC"
        )
        .fetch_all(pool)
        .await?;
        
        Ok(vulns)
    }
}

pub struct ProjectOperations;

impl ProjectOperations {
    pub async fn create(pool: &SqlitePool, name: &str, description: Option<&str>) -> Result<Project> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let project = sqlx::query_as!(
            Project,
            r#"
            INSERT INTO projects (id, name, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING *
            "#,
            id,
            name,
            description,
            now,
            now
        )
        .fetch_one(pool)
        .await?;
        
        Ok(project)
    }

    pub async fn list_all(pool: &SqlitePool) -> Result<Vec<Project>> {
        let projects = sqlx::query_as!(
            Project,
            "SELECT * FROM projects ORDER BY updated_at DESC"
        )
        .fetch_all(pool)
        .await?;
        
        Ok(projects)
    }
}

    pub async fn find_by_id(pool: &SqlitePool, project_id: &str) -> Result<Option<Project>> {
        let project = sqlx::query_as!(
            Project,
            "SELECT * FROM projects WHERE id = ?",
            project_id
        )
        .fetch_optional(pool)
        .await?;
        
        Ok(project)
    }

    pub async fn update_description(
        pool: &SqlitePool,
        project_id: &str,
        description: Option<&str>,
    ) -> Result<()> {
        sqlx::query!(
            "UPDATE projects SET description = ?, updated_at = ? WHERE id = ?",
            description,
            Utc::now(),
            project_id
        )
        .execute(pool)
        .await?;
        
        Ok(())
    }
}