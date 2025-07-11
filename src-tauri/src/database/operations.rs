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

use crate::database::models::{Host, HostStatus};
use crate::shared::{StoredPort, StoredVulnerability, Protocol, PortState, Severity};
use std::str::FromStr;
use sqlx::SqlitePool;
use uuid::Uuid;
use anyhow::Result;
use chrono::Utc;

// High-performance database operations
pub struct DatabaseOperations {
    pool: SqlitePool,
}

impl DatabaseOperations {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // HOST OPERATIONS - Core functionality

    /// Upsert host - insert or update if exists
    pub async fn upsert_host(&self, ip: &str, hostname: Option<&str>) -> Result<Host> {
        let now = Utc::now();
        let host_id = Uuid::new_v4().to_string();
        
        // Check if host exists
        if let Ok(existing_host) = self.get_host_by_ip(ip).await {
            // Update existing host
            let mut updated_host = existing_host;
            updated_host.hostname = hostname.map(|h| h.to_string());
            updated_host.last_seen = now;
            updated_host.updated_at = now;
            
            let last_seen_str = now.to_rfc3339();
            let updated_at_str = now.to_rfc3339();
            sqlx::query!(
                r#"
                UPDATE hosts 
                SET hostname = ?, last_seen = ?, updated_at = ?
                WHERE ip = ?
                "#,
                hostname,
                last_seen_str,
                updated_at_str,
                ip
            )
            .execute(&self.pool)
            .await?;
            
            return Ok(updated_host);
        }
        
        // Insert new host
        let host = Host {
            id: host_id.clone(),
            ip: ip.to_string(),
            hostname: hostname.map(|h| h.to_string()),
            mac_address: None,
            vendor: None,
            os_name: None,
            os_family: None,
            os_accuracy: None,
            status: HostStatus::Unknown,
            last_seen: now,
            created_at: now,
            updated_at: now,
            port_count: 0,
            vulnerability_count: 0,
            notes: None,
            tags: Vec::new(),
            scan_progress: None,
        };
        
        let status_str = host.status.to_string();
        let last_seen_str = host.last_seen.to_rfc3339();
        let created_at_str = host.created_at.to_rfc3339();
        let updated_at_str = host.updated_at.to_rfc3339();
        sqlx::query!(
            r#"
            INSERT INTO hosts (
                id, ip, hostname, mac_address, vendor, os_name, os_family, 
                os_accuracy, status, last_seen, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            host.id,
            host.ip,
            host.hostname,
            host.mac_address,
            host.vendor,
            host.os_name,
            host.os_family,
            host.os_accuracy,
            status_str,
            last_seen_str,
            created_at_str,
            updated_at_str
        )
        .execute(&self.pool)
        .await?;
        
        Ok(host)
    }

    /// Get host by IP address
    pub async fn get_host_by_ip(&self, ip: &str) -> Result<Host> {
        let row = sqlx::query!(
            "SELECT id, ip, hostname, mac_address, vendor, os_name, os_family, os_accuracy, status, port_count, vulnerability_count, last_seen, created_at, updated_at, notes, tags, scan_progress FROM hosts WHERE ip = ?",
            ip
        )
        .fetch_one(&self.pool)
        .await?;
    

        let status = HostStatus::from_str(&row.status)?;
        let tags: Vec<String> = serde_json::from_str(if row.tags.is_empty() { "[]" } else { &row.tags })?;

        Ok(Host {
            id: row.id.unwrap_or_default(),
            ip: row.ip,
            hostname: row.hostname,
            mac_address: row.mac_address,
            vendor: row.vendor,
            os_name: row.os_name,
            os_family: row.os_family,
            os_accuracy: row.os_accuracy.map(|f| f as f32),
            status,
            last_seen: chrono::DateTime::parse_from_rfc3339(&row.last_seen)?.with_timezone(&chrono::Utc),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.updated_at)?.with_timezone(&chrono::Utc),
            port_count: row.port_count as i32,
            vulnerability_count: row.vulnerability_count as i32,
            notes: row.notes,
            tags,
            scan_progress: row.scan_progress.map(|f| f as f32),
        })
    }

    /// Get all hosts with optional filtering
    pub async fn get_hosts(&self, status_filter: Option<HostStatus>) -> Result<Vec<Host>> {
        #[derive(sqlx::FromRow)]
        struct HostRow {
            id: Option<String>,
            ip: String,
            hostname: Option<String>,
            mac_address: Option<String>,
            vendor: Option<String>,
            os_name: Option<String>,
            os_family: Option<String>,
            os_accuracy: Option<f64>,
            status: String,
            port_count: i64,
            vulnerability_count: i64,
            last_seen: String,
            created_at: String,
            updated_at: String,
            notes: Option<String>,
            tags: String,
            scan_progress: Option<f64>,
        }

        let rows = if let Some(status) = status_filter {
            let status_str = status.to_string();
            sqlx::query_as!(
                HostRow,
                "SELECT id, ip, hostname, mac_address, vendor, os_name, os_family, os_accuracy, status, port_count, vulnerability_count, last_seen, created_at, updated_at, notes, tags, scan_progress FROM hosts WHERE status = ? ORDER BY last_seen DESC",
                status_str
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as!(HostRow, "SELECT id, ip, hostname, mac_address, vendor, os_name, os_family, os_accuracy, status, port_count, vulnerability_count, last_seen, created_at, updated_at, notes, tags, scan_progress FROM hosts ORDER BY last_seen DESC")
                .fetch_all(&self.pool)
                .await?
        };
        
        let mut hosts = Vec::new();
        for row in rows {
            let status = HostStatus::from_str(&row.status)?;
            let tags: Vec<String> = serde_json::from_str(if row.tags.is_empty() { "[]" } else { &row.tags })?;

            hosts.push(Host {
                id: row.id.unwrap_or_default(),
                ip: row.ip,
                hostname: row.hostname,
                mac_address: row.mac_address,
                vendor: row.vendor,
                os_name: row.os_name,
                os_family: row.os_family,
                os_accuracy: row.os_accuracy.map(|f| f as f32),
                status,
                last_seen: chrono::DateTime::parse_from_rfc3339(&row.last_seen)?.with_timezone(&chrono::Utc),
                created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&row.updated_at)?.with_timezone(&chrono::Utc),
                port_count: row.port_count as i32,
                vulnerability_count: row.vulnerability_count as i32,
                notes: row.notes,
                tags,
                scan_progress: row.scan_progress.map(|f| f as f32),
            });
        }
        
        Ok(hosts)
    }

    /// Update host status and scanning progress
    pub async fn update_host_status(&self, host_id: &str, status: HostStatus, _progress: Option<f32>) -> Result<()> {
        let now = Utc::now();
        let status_str = status.to_string();
        let updated_at_str = now.to_rfc3339();
        let last_seen_str = now.to_rfc3339();
        
        sqlx::query!(
            r#"
            UPDATE hosts 
            SET status = ?, updated_at = ?, last_seen = ?
            WHERE id = ?
            "#,
            status_str,
            updated_at_str,
            last_seen_str,
            host_id
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }

    /// Update host OS information
    pub async fn update_host_os(&self, host_id: &str, os_name: &str, os_family: &str, accuracy: f32) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query!(
            r#"
            UPDATE hosts 
            SET os_name = ?, os_family = ?, os_accuracy = ?, updated_at = ?
            WHERE id = ?
            "#,
            os_name,
            os_family,
            accuracy,
            now,
            host_id
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }

    /// Delete host and all associated data
    pub async fn delete_host(&self, host_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        
        // Delete vulnerabilities first (foreign key constraint)
        sqlx::query!("DELETE FROM vulnerabilities WHERE host_id = ?", host_id)
            .execute(&mut *tx)
            .await?;
            
        // Delete ports
        sqlx::query!("DELETE FROM ports WHERE host_id = ?", host_id)
            .execute(&mut *tx)
            .await?;
            
        // Delete host
        sqlx::query!("DELETE FROM hosts WHERE id = ?", host_id)
            .execute(&mut *tx)
            .await?;
            
        tx.commit().await?;
        Ok(())
    }

    // PORT OPERATIONS

    /// Add port to host
    pub async fn add_port(&self, port: &StoredPort) -> Result<()> {
        let protocol_str = match port.protocol { Protocol::Tcp => "tcp", Protocol::Udp => "udp" };
        let state_str = match port.state {
            PortState::Open => "open", 
            PortState::Closed => "closed", 
            PortState::Filtered => "filtered",
            PortState::Unknown => "unknown",
        };
        let cpe_json = serde_json::to_string(&port.cpe)?;
        let discovered_at_str = port.discovered_at.to_rfc3339();
        let last_seen_str = port.last_seen.to_rfc3339();

        sqlx::query!(
            r#"            INSERT INTO ports (
                id, host_id, number, protocol, state, service, version, 
                banner, confidence, cpe, discovered_at, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            port.id,
            port.host_id,
            port.number,
            protocol_str,
            state_str,
            port.service,
            port.version,
            port.banner,
            port.confidence,
            cpe_json,
            discovered_at_str,
            last_seen_str
        )
        .execute(&self.pool)
        .await?;
        
        // Update host port count
        self.update_host_port_count(&port.host_id).await?;
        
        Ok(())
    }

    /// Get ports for host
    pub async fn get_host_ports(&self, host_id: &str) -> Result<Vec<StoredPort>> {
        let rows = sqlx::query!(
            "SELECT id, host_id, number, protocol, state, service, version, banner, confidence, cpe, discovered_at, last_seen FROM ports WHERE host_id = ? ORDER BY number",
            host_id
        )
        .fetch_all(&self.pool)
        .await?;
        
        let mut ports = Vec::new();
        for row in rows {
            let cpe: Vec<String> = serde_json::from_str(&row.cpe.unwrap_or("[]".to_string()))?;
            ports.push(StoredPort {
                id: row.id.unwrap_or_default(),
                host_id: row.host_id,
                number: row.number as i32,
                protocol: Protocol::from_str(&row.protocol)?,
                state: PortState::from_str(&row.state)?,
                service: row.service,
                version: row.version,
                banner: row.banner,
                confidence: row.confidence.map(|c| c as f32),
                cpe,
                discovered_at: chrono::DateTime::parse_from_rfc3339(&row.discovered_at)?.with_timezone(&chrono::Utc),
                last_seen: chrono::DateTime::parse_from_rfc3339(&row.last_seen)?.with_timezone(&chrono::Utc),
            });
        }
        
        Ok(ports)
    }

    // VULNERABILITY OPERATIONS

    /// Add vulnerability to host
    pub async fn add_vulnerability(&self, vulnerability: &StoredVulnerability) -> Result<()> {
        let severity_str = match vulnerability.severity {
            Severity::Info => "info",
            Severity::Low => "low", 
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        let reference_links_json = serde_json::to_string(&vulnerability.reference_links)?;
        let discovered_at_str = vulnerability.discovered_at.to_rfc3339();

        sqlx::query!(
            r#"            INSERT INTO vulnerabilities (
                id, host_id, port_id, name, severity, description, 
                cvss_score, cvss_vector, cve_id, reference_links, exploitable, 
                discovered_at, verified, false_positive
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            vulnerability.id,
            vulnerability.host_id,
            vulnerability.port_id,
            vulnerability.name,
            severity_str,
            vulnerability.description,
            vulnerability.cvss_score,
            vulnerability.cvss_vector,
            vulnerability.cve_id,
            reference_links_json,
            vulnerability.exploitable,
            discovered_at_str,
            vulnerability.verified,
            vulnerability.false_positive
        )
        .execute(&self.pool)
        .await?;
        
        // Update host vulnerability count
        self.update_host_vulnerability_count(&vulnerability.host_id).await?;
        
        Ok(())
    }

    /// Get vulnerabilities for host
    pub async fn get_host_vulnerabilities(&self, host_id: &str) -> Result<Vec<StoredVulnerability>> {
        let rows = sqlx::query!(
            "SELECT id, host_id, port_id, name, severity, description, cvss_score, cvss_vector, cve_id, reference_links, exploitable, discovered_at, verified, false_positive FROM vulnerabilities WHERE host_id = ? ORDER BY severity, name",
            host_id
        )
        .fetch_all(&self.pool)
        .await?;
        
        let mut vulnerabilities = Vec::new();
        for row in rows {
            let severity = Severity::from_str(&row.severity)?;
            let reference_links: Vec<String> = serde_json::from_str(&row.reference_links.unwrap_or("[]".to_string()))?;
            
            vulnerabilities.push(StoredVulnerability {
                id: row.id.unwrap_or_default(),
                host_id: row.host_id,
                port_id: row.port_id,
                name: row.name,
                severity,
                description: row.description,
                cvss_score: row.cvss_score.map(|s| s as f32),
                cvss_vector: row.cvss_vector,
                cve_id: row.cve_id,
                reference_links,
                exploitable: row.exploitable,
                discovered_at: chrono::DateTime::parse_from_rfc3339(&row.discovered_at)?.with_timezone(&chrono::Utc),
                verified: row.verified,
                false_positive: row.false_positive,
            });
        }
        
        Ok(vulnerabilities)
    }

    

    async fn update_host_port_count(&self, host_id: &str) -> Result<()> {
        let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM ports WHERE host_id = ?")
            .bind(host_id)
            .fetch_one(&self.pool)
            .await?;
        
        sqlx::query("UPDATE hosts SET port_count = ? WHERE id = ?")
            .bind(count)
            .bind(host_id)
            .execute(&self.pool)
            .await?;
            
        Ok(())
    }

    async fn update_host_vulnerability_count(&self, host_id: &str) -> Result<()> {
        let count: i32 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE host_id = ?")
            .bind(host_id)
            .fetch_one(&self.pool)
            .await?;

        sqlx::query("UPDATE hosts SET vulnerability_count = ? WHERE id = ?")
            .bind(count)
            .bind(host_id)
            .execute(&self.pool)
            .await?;
            
        Ok(())
    }
}