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

use crate::shared::{
    Host, HostStatus, PortState, Protocol, Severity, StoredPort, StoredVulnerability,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::str::FromStr;
use std::sync::Mutex;
use uuid::Uuid;

/// Database operations using rusqlite
pub struct DatabaseOperations {
    conn: Mutex<Connection>,
}

impl DatabaseOperations {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    pub fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            
            CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY,
                ip TEXT UNIQUE NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                vendor TEXT,
                os_name TEXT,
                os_family TEXT,
                os_accuracy REAL,
                status TEXT NOT NULL DEFAULT 'unknown',
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                port_count INTEGER DEFAULT 0,
                vulnerability_count INTEGER DEFAULT 0,
                notes TEXT,
                tags TEXT DEFAULT '[]',
                scan_progress REAL
            );
            
            CREATE TABLE IF NOT EXISTS ports (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                number INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service TEXT,
                version TEXT,
                banner TEXT,
                confidence REAL,
                cpe TEXT DEFAULT '[]',
                discovered_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                UNIQUE(host_id, number, protocol)
            );
            
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                port_id TEXT,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                cvss_score REAL,
                cvss_vector TEXT,
                cve_id TEXT,
                reference_links TEXT DEFAULT '[]',
                exploitable INTEGER DEFAULT 0,
                discovered_at TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0,
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
            );
        "#,
        )?;

        Ok(())
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

            let conn = self.conn.lock().unwrap();
            conn.execute(
                "UPDATE hosts SET hostname = ?, last_seen = ?, updated_at = ? WHERE ip = ?",
                params![hostname, now.to_rfc3339(), now.to_rfc3339(), ip],
            )?;

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

        let tags_json = serde_json::to_string(&host.tags)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO hosts (
                id, ip, hostname, mac_address, vendor, os_name, os_family, 
                os_accuracy, status, last_seen, created_at, updated_at, 
                port_count, vulnerability_count, notes, tags, scan_progress
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            params![
                host.id,
                host.ip,
                host.hostname,
                host.mac_address,
                host.vendor,
                host.os_name,
                host.os_family,
                host.os_accuracy,
                host.status.to_string(),
                host.last_seen.to_rfc3339(),
                host.created_at.to_rfc3339(),
                host.updated_at.to_rfc3339(),
                host.port_count,
                host.vulnerability_count,
                host.notes,
                tags_json,
                host.scan_progress
            ],
        )?;

        Ok(host)
    }

    /// Get host by IP
    pub async fn get_host_by_ip(&self, ip: &str) -> Result<Host> {
        let conn = self.conn.lock().unwrap();

        let host = conn.query_row(
            r#"
            SELECT id, ip, hostname, mac_address, vendor, os_name, os_family,
                   os_accuracy, status, last_seen, created_at, updated_at,
                   port_count, vulnerability_count, notes, tags, scan_progress
            FROM hosts WHERE ip = ?1
            "#,
            params![ip],
            |row| {
                let tags_str: String = row.get("tags")?;
                let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();

                Ok(Host {
                    id: row.get("id")?,
                    ip: row.get("ip")?,
                    hostname: row.get("hostname")?,
                    mac_address: row.get("mac_address")?,
                    vendor: row.get("vendor")?,
                    os_name: row.get("os_name")?,
                    os_family: row.get("os_family")?,
                    os_accuracy: row.get("os_accuracy")?,
                    status: HostStatus::from_str(&row.get::<_, String>("status")?)
                        .unwrap_or(HostStatus::Unknown),
                    last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>("last_seen")?)
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?
                        .with_timezone(&Utc),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>("created_at")?)
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?
                        .with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>("updated_at")?)
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?
                        .with_timezone(&Utc),
                    port_count: row.get("port_count")?,
                    vulnerability_count: row.get("vulnerability_count")?,
                    notes: row.get("notes")?,
                    tags,
                    scan_progress: row.get("scan_progress")?,
                })
            },
        )?;

        Ok(host)
    }

    /// Helper function to parse a host from a row
    fn parse_host_row(row: &rusqlite::Row) -> rusqlite::Result<Host> {
        let tags_str: String = row.get("tags")?;
        let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();

        Ok(Host {
            id: row.get("id")?,
            ip: row.get("ip")?,
            hostname: row.get("hostname")?,
            mac_address: row.get("mac_address")?,
            vendor: row.get("vendor")?,
            os_name: row.get("os_name")?,
            os_family: row.get("os_family")?,
            os_accuracy: row.get("os_accuracy")?,
            status: HostStatus::from_str(&row.get::<_, String>("status")?)
                .unwrap_or(HostStatus::Unknown),
            last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>("last_seen")?)
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?
                .with_timezone(&Utc),
            created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>("created_at")?)
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>("updated_at")?)
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?
                .with_timezone(&Utc),
            port_count: row.get("port_count")?,
            vulnerability_count: row.get("vulnerability_count")?,
            notes: row.get("notes")?,
            tags,
            scan_progress: row.get("scan_progress")?,
        })
    }

    /// Get all hosts with optional filtering
    pub async fn get_hosts(&self, status_filter: Option<HostStatus>) -> Result<Vec<Host>> {
        let conn = self.conn.lock().unwrap();

        let query = if status_filter.is_some() {
            "SELECT id, ip, hostname, mac_address, vendor, os_name, os_family, os_accuracy, status, port_count, vulnerability_count, last_seen, created_at, updated_at, notes, tags, scan_progress FROM hosts WHERE status = ?1 ORDER BY last_seen DESC"
        } else {
            "SELECT id, ip, hostname, mac_address, vendor, os_name, os_family, os_accuracy, status, port_count, vulnerability_count, last_seen, created_at, updated_at, notes, tags, scan_progress FROM hosts ORDER BY last_seen DESC"
        };

        let mut stmt = conn.prepare(query)?;
        let rows = if let Some(status) = status_filter {
            stmt.query_map(params![status.to_string()], Self::parse_host_row)?
        } else {
            stmt.query_map([], Self::parse_host_row)?
        };

        let mut hosts = Vec::new();
        for row in rows {
            hosts.push(row?);
        }

        Ok(hosts)
    }

    /// Update host status
    pub async fn update_host_status(
        &self,
        host_id: &str,
        status: HostStatus,
        progress: Option<f32>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "UPDATE hosts SET status = ?1, scan_progress = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                status.to_string(),
                progress,
                Utc::now().to_rfc3339(),
                host_id
            ],
        )?;

        Ok(())
    }

    /// Update host OS information
    pub async fn update_host_os(
        &self,
        host_id: &str,
        os_name: &str,
        os_family: &str,
        accuracy: f32,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE hosts SET os_name = ?1, os_family = ?2, os_accuracy = ?3, updated_at = ?4 WHERE id = ?5",
            params![os_name, os_family, accuracy, now, host_id],
        )?;

        Ok(())
    }

    /// Store port information
    pub async fn store_port(&self, port: &StoredPort) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let cpe_json = serde_json::to_string(&port.cpe)?;

        conn.execute(
            r#"
            INSERT INTO ports (
                id, host_id, number, protocol, state, service, version,
                banner, confidence, cpe, discovered_at, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(host_id, number, protocol) DO UPDATE SET
                state = ?5,
                service = COALESCE(?6, service),
                version = COALESCE(?7, version),
                banner = COALESCE(?8, banner),
                confidence = COALESCE(?9, confidence),
                cpe = ?10,
                last_seen = ?12
            "#,
            params![
                port.id,
                port.host_id,
                port.number,
                port.protocol.to_string(),
                port.state.to_string(),
                port.service,
                port.version,
                port.banner,
                port.confidence,
                cpe_json,
                port.discovered_at.to_rfc3339(),
                port.last_seen.to_rfc3339()
            ],
        )?;

        Ok(())
    }

    /// Delete host
    pub async fn delete_host(&self, host_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        // Delete vulnerabilities first
        conn.execute(
            "DELETE FROM vulnerabilities WHERE host_id = ?1",
            params![host_id],
        )?;

        // Delete ports
        conn.execute("DELETE FROM ports WHERE host_id = ?1", params![host_id])?;

        // Delete host
        conn.execute("DELETE FROM hosts WHERE id = ?1", params![host_id])?;

        Ok(())
    }

    // PORT OPERATIONS

    /// Add port to host
    pub async fn add_port(&self, port: &StoredPort) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let cpe_json = serde_json::to_string(&port.cpe)?;

        conn.execute(
            r#"
            INSERT INTO ports (
                id, host_id, number, protocol, state, service, version, 
                banner, confidence, cpe, discovered_at, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(host_id, number, protocol) DO UPDATE SET
                state = ?5,
                service = COALESCE(?6, service),
                version = COALESCE(?7, version),
                banner = COALESCE(?8, banner),
                confidence = COALESCE(?9, confidence),
                cpe = ?10,
                last_seen = ?12
            "#,
            params![
                port.id,
                port.host_id,
                port.number,
                port.protocol.to_string(),
                port.state.to_string(),
                port.service,
                port.version,
                port.banner,
                port.confidence,
                cpe_json,
                port.discovered_at.to_rfc3339(),
                port.last_seen.to_rfc3339()
            ],
        )?;

        // Update host port count
        self.update_host_port_count(&port.host_id).await?;

        Ok(())
    }

    /// Get ports for host
    pub async fn get_host_ports(&self, host_id: &str) -> Result<Vec<StoredPort>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, host_id, number, protocol, state, service, version, banner, confidence, cpe, discovered_at, last_seen FROM ports WHERE host_id = ?1 ORDER BY number"
        )?;

        let rows = stmt.query_map(params![host_id], |row| {
            let cpe_str: String = row.get("cpe")?;
            let cpe: Vec<String> = serde_json::from_str(&cpe_str).unwrap_or_default();

            Ok(StoredPort {
                id: row.get("id")?,
                host_id: row.get("host_id")?,
                number: row.get("number")?,
                protocol: Protocol::from_str(&row.get::<_, String>("protocol")?)
                    .unwrap_or(Protocol::Tcp),
                state: PortState::from_str(&row.get::<_, String>("state")?)
                    .unwrap_or(PortState::Unknown),
                service: row.get("service")?,
                version: row.get("version")?,
                banner: row.get("banner")?,
                confidence: row.get("confidence")?,
                cpe,
                discovered_at: DateTime::parse_from_rfc3339(
                    &row.get::<_, String>("discovered_at")?,
                )
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?
                .with_timezone(&Utc),
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>("last_seen")?)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?
                    .with_timezone(&Utc),
            })
        })?;

        let mut ports = Vec::new();
        for row in rows {
            ports.push(row?);
        }

        Ok(ports)
    }

    // VULNERABILITY OPERATIONS

    /// Add vulnerability to host
    pub async fn add_vulnerability(&self, vulnerability: &StoredVulnerability) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let reference_links_json = serde_json::to_string(&vulnerability.reference_links)?;

        conn.execute(
            r#"
            INSERT INTO vulnerabilities (
                id, host_id, port_id, name, severity, description, 
                cvss_score, cvss_vector, cve_id, reference_links, exploitable, 
                discovered_at, verified, false_positive
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                vulnerability.id,
                vulnerability.host_id,
                vulnerability.port_id,
                vulnerability.name,
                vulnerability.severity.to_string(),
                vulnerability.description,
                vulnerability.cvss_score,
                vulnerability.cvss_vector,
                vulnerability.cve_id,
                reference_links_json,
                vulnerability.exploitable,
                vulnerability.discovered_at.to_rfc3339(),
                vulnerability.verified,
                vulnerability.false_positive
            ],
        )?;

        // Update host vulnerability count
        self.update_host_vulnerability_count(&vulnerability.host_id)
            .await?;

        Ok(())
    }

    /// Get vulnerabilities for host
    pub async fn get_host_vulnerabilities(
        &self,
        host_id: &str,
    ) -> Result<Vec<StoredVulnerability>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, host_id, port_id, name, severity, description, cvss_score, cvss_vector, cve_id, reference_links, exploitable, discovered_at, verified, false_positive FROM vulnerabilities WHERE host_id = ?1 ORDER BY severity, name"
        )?;

        let rows = stmt.query_map(params![host_id], |row| {
            let reference_links_str: String = row.get("reference_links")?;
            let reference_links: Vec<String> =
                serde_json::from_str(&reference_links_str).unwrap_or_default();

            Ok(StoredVulnerability {
                id: row.get("id")?,
                host_id: row.get("host_id")?,
                port_id: row.get("port_id")?,
                name: row.get("name")?,
                severity: Severity::from_str(&row.get::<_, String>("severity")?)
                    .unwrap_or(Severity::Info),
                description: row.get("description")?,
                cvss_score: row.get("cvss_score")?,
                cvss_vector: row.get("cvss_vector")?,
                cve_id: row.get("cve_id")?,
                reference_links,
                exploitable: row.get("exploitable")?,
                discovered_at: DateTime::parse_from_rfc3339(
                    &row.get::<_, String>("discovered_at")?,
                )
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?
                .with_timezone(&Utc),
                verified: row.get("verified")?,
                false_positive: row.get("false_positive")?,
            })
        })?;

        let mut vulnerabilities = Vec::new();
        for row in rows {
            vulnerabilities.push(row?);
        }

        Ok(vulnerabilities)
    }

    /// Get vulnerability statistics
    pub async fn get_vulnerability_stats(&self) -> Result<std::collections::HashMap<String, i32>> {
        let conn = self.conn.lock().unwrap();

        let mut stats = std::collections::HashMap::new();

        let total: i32 =
            conn.query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))?;
        stats.insert("total".to_string(), total);

        // Count by severity
        let mut stmt =
            conn.prepare("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity")?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?;

        for row in rows {
            let (severity, count) = row?;
            stats.insert(severity, count);
        }

        Ok(stats)
    }

    /// Get host by ID
    pub async fn get_host_by_id(&self, host_id: &str) -> Result<Host> {
        let conn = self.conn.lock().unwrap();

        let host = conn.query_row(
            r#"
            SELECT id, ip, hostname, mac_address, vendor, os_name, os_family,
                   os_accuracy, status, last_seen, created_at, updated_at,
                   port_count, vulnerability_count, notes, tags, scan_progress
            FROM hosts WHERE id = ?1
            "#,
            params![host_id],
            |row| {
                let tags_str: String = row.get("tags")?;
                let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();

                Ok(Host {
                    id: row.get("id")?,
                    ip: row.get("ip")?,
                    hostname: row.get("hostname")?,
                    mac_address: row.get("mac_address")?,
                    vendor: row.get("vendor")?,
                    os_name: row.get("os_name")?,
                    os_family: row.get("os_family")?,
                    os_accuracy: row.get("os_accuracy")?,
                    status: HostStatus::from_str(&row.get::<_, String>("status")?)
                        .unwrap_or(HostStatus::Unknown),
                    last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>("last_seen")?)
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?
                        .with_timezone(&Utc),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>("created_at")?)
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?
                        .with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>("updated_at")?)
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?
                        .with_timezone(&Utc),
                    port_count: row.get("port_count")?,
                    vulnerability_count: row.get("vulnerability_count")?,
                    notes: row.get("notes")?,
                    tags,
                    scan_progress: row.get("scan_progress")?,
                })
            },
        )?;

        Ok(host)
    }

    /// Update host notes
    pub async fn update_host_notes(&self, host_id: &str, notes: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "UPDATE hosts SET notes = ?1, updated_at = ?2 WHERE id = ?3",
            params![notes, Utc::now().to_rfc3339(), host_id],
        )?;

        Ok(())
    }

    /// Update host tags
    pub async fn update_host_tags(&self, host_id: &str, tags: &[String]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tags_json = serde_json::to_string(tags)?;

        conn.execute(
            "UPDATE hosts SET tags = ?1, updated_at = ?2 WHERE id = ?3",
            params![tags_json, Utc::now().to_rfc3339(), host_id],
        )?;

        Ok(())
    }

    /// Search hosts by various criteria
    pub async fn search_hosts(&self, query: &str) -> Result<Vec<Host>> {
        let conn = self.conn.lock().unwrap();
        let search_term = format!("%{}%", query);

        let mut stmt = conn.prepare(
            r#"
            SELECT id, ip, hostname, mac_address, vendor, os_name, os_family,
                   os_accuracy, status, last_seen, created_at, updated_at,
                   port_count, vulnerability_count, notes, tags, scan_progress
            FROM hosts 
            WHERE ip LIKE ?1 OR hostname LIKE ?1 OR os_name LIKE ?1 OR notes LIKE ?1
            ORDER BY last_seen DESC
            "#,
        )?;

        let rows = stmt.query_map(params![search_term], Self::parse_host_row)?;

        let mut hosts = Vec::new();
        for row in rows {
            hosts.push(row?);
        }

        Ok(hosts)
    }

    /// Batch insert hosts with transaction support
    pub async fn batch_upsert_hosts(&self, hosts: &[Host]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;

        let mut stmt = tx.prepare(
            r#"
            INSERT INTO hosts (
                id, ip, hostname, mac_address, vendor, os_name, os_family, 
                os_accuracy, status, last_seen, created_at, updated_at,
                port_count, vulnerability_count, notes, tags, scan_progress
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            ON CONFLICT(ip) DO UPDATE SET
                hostname = COALESCE(?3, hostname),
                mac_address = COALESCE(?4, mac_address),
                vendor = COALESCE(?5, vendor),
                os_name = COALESCE(?6, os_name),
                os_family = COALESCE(?7, os_family),
                os_accuracy = COALESCE(?8, os_accuracy),
                status = ?9,
                last_seen = ?10,
                updated_at = ?12,
                port_count = ?13,
                vulnerability_count = ?14,
                notes = COALESCE(?15, notes),
                tags = ?16,
                scan_progress = ?17
            "#,
        )?;

        for host in hosts {
            let tags_json = serde_json::to_string(&host.tags)?;
            stmt.execute(params![
                host.id,
                host.ip,
                host.hostname,
                host.mac_address,
                host.vendor,
                host.os_name,
                host.os_family,
                host.os_accuracy,
                host.status.to_string(),
                host.last_seen.to_rfc3339(),
                host.created_at.to_rfc3339(),
                host.updated_at.to_rfc3339(),
                host.port_count,
                host.vulnerability_count,
                host.notes,
                tags_json,
                host.scan_progress
            ])?;
        }

        drop(stmt); // Explicitly drop the statement before committing
        tx.commit()?;
        Ok(())
    }

    /// Batch insert ports with transaction support
    pub async fn batch_insert_ports(&self, ports: &[StoredPort]) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        {
            let tx = conn.unchecked_transaction()?;

            let mut stmt = tx.prepare(
                r#"
                INSERT INTO ports (
                    id, host_id, number, protocol, state, service, version,
                    banner, confidence, cpe, discovered_at, last_seen
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                ON CONFLICT(host_id, number, protocol) DO UPDATE SET
                    state = ?5,
                    service = COALESCE(?6, service),
                    version = COALESCE(?7, version),
                    banner = COALESCE(?8, banner),
                    confidence = COALESCE(?9, confidence),
                    cpe = ?10,
                    last_seen = ?12
                "#,
            )?;

            for port in ports {
                let cpe_json = serde_json::to_string(&port.cpe)?;
                stmt.execute(params![
                    port.id,
                    port.host_id,
                    port.number,
                    port.protocol.to_string(),
                    port.state.to_string(),
                    port.service,
                    port.version,
                    port.banner,
                    port.confidence,
                    cpe_json,
                    port.discovered_at.to_rfc3339(),
                    port.last_seen.to_rfc3339()
                ])?;
            }

            drop(stmt); // Explicitly drop the statement before committing
            tx.commit()?;
        }

        // Update port counts for affected hosts after transaction is complete
        let host_ids: std::collections::HashSet<_> =
            ports.iter().map(|p| p.host_id.as_str()).collect();
        drop(conn); // Release the connection lock before calling other methods

        for host_id in host_ids {
            self.update_host_port_count(host_id).await?;
        }

        Ok(())
    }

    /// Batch insert vulnerabilities with transaction support
    pub async fn batch_insert_vulnerabilities(
        &self,
        vulnerabilities: &[StoredVulnerability],
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        {
            let tx = conn.unchecked_transaction()?;

            let mut stmt = tx.prepare(
                r#"
                INSERT INTO vulnerabilities (
                    id, host_id, port_id, name, severity, description, 
                    cvss_score, cvss_vector, cve_id, reference_links, exploitable, 
                    discovered_at, verified, false_positive
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
            )?;

            for vulnerability in vulnerabilities {
                let reference_links_json = serde_json::to_string(&vulnerability.reference_links)?;
                stmt.execute(params![
                    vulnerability.id,
                    vulnerability.host_id,
                    vulnerability.port_id,
                    vulnerability.name,
                    vulnerability.severity.to_string(),
                    vulnerability.description,
                    vulnerability.cvss_score,
                    vulnerability.cvss_vector,
                    vulnerability.cve_id,
                    reference_links_json,
                    vulnerability.exploitable,
                    vulnerability.discovered_at.to_rfc3339(),
                    vulnerability.verified,
                    vulnerability.false_positive
                ])?;
            }

            drop(stmt); // Explicitly drop the statement before committing
            tx.commit()?;
        }

        // Update vulnerability counts for affected hosts after transaction is complete
        let host_ids: std::collections::HashSet<_> =
            vulnerabilities.iter().map(|v| v.host_id.as_str()).collect();
        drop(conn); // Release the connection lock before calling other methods

        for host_id in host_ids {
            self.update_host_vulnerability_count(host_id).await?;
        }

        Ok(())
    }

    async fn update_host_port_count(&self, host_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM ports WHERE host_id = ?1",
            params![host_id],
            |row| row.get(0),
        )?;

        conn.execute(
            "UPDATE hosts SET port_count = ?1 WHERE id = ?2",
            params![count, host_id],
        )?;

        Ok(())
    }

    async fn update_host_vulnerability_count(&self, host_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE host_id = ?1",
            params![host_id],
            |row| row.get(0),
        )?;

        conn.execute(
            "UPDATE hosts SET vulnerability_count = ?1 WHERE id = ?2",
            params![count, host_id],
        )?;

        Ok(())
    }
}
