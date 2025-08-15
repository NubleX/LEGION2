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

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::shared::{Host, HostStatus};

// ------------- internal helpers (shared) -------------

fn to_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}
fn from_rfc3339(s: &str) -> DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn encode_tags(tags: &[String]) -> String {
    serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string())
}

fn decode_tags(s: Option<String>) -> Vec<String> {
    match s {
        Some(v) => serde_json::from_str(&v).unwrap_or_default(),
        None => Vec::new(),
    }
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS hosts (
            id              TEXT PRIMARY KEY,
            ip              TEXT UNIQUE NOT NULL,
            hostname        TEXT,
            mac_address     TEXT,
            vendor          TEXT,
            os_name         TEXT,
            os_family       TEXT,
            os_accuracy     REAL,
            status          TEXT NOT NULL DEFAULT 'unknown',
            first_seen      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            port_count          INTEGER NOT NULL DEFAULT 0,
            vulnerability_count INTEGER NOT NULL DEFAULT 0,
            notes           TEXT,
            tags            TEXT,
            scan_progress   REAL
        );

        CREATE TABLE IF NOT EXISTS ports (
            id           TEXT PRIMARY KEY,
            host_id      TEXT NOT NULL,
            number       INTEGER NOT NULL,
            protocol     TEXT NOT NULL,
            state        TEXT,
            service_name TEXT,
            product      TEXT,
            version      TEXT,
            reason       TEXT,
            banner       TEXT,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            UNIQUE(host_id, number, protocol),
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id            TEXT PRIMARY KEY,
            host_id       TEXT NOT NULL,
            port_id       TEXT,
            name          TEXT NOT NULL,
            severity      TEXT NOT NULL,
            description   TEXT,
            cve           TEXT,
            cvss_score    REAL,
            discovered_at TEXT NOT NULL,
            last_seen     TEXT NOT NULL,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE SET NULL
        );
    "#,
    )?;
    
    // Try to create indexes, but ignore errors for missing columns
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_ports_num_proto ON ports(number, protocol)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id)", []);

    Ok(())
}

// ------------- your original simple Db (kept) -------------

#[derive(Debug)]
pub struct Db {
    pub(crate) conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        ensure_schema(&conn)?; // use the full schema now
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub async fn upsert_host(&self, ip: &str, hostname: Option<&str>) -> Result<()> {
        let ts = Utc::now();
        let t = ts.to_rfc3339();
        
        // Use spawn_blocking to run database operations on a blocking thread
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let hostname = hostname.map(|h| h.to_string());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            
            // If no row, insert with the extended columns initialized;
            // if exists, just bump last_seen.
            conn.execute(
                r#"INSERT INTO hosts(id, ip, first_seen, last_seen, created_at, updated_at, status, tags, port_count, vulnerability_count)
                   VALUES(?1, ?2, ?3, ?3, ?3, ?3, 'unknown', '[]', 0, 0)
                   ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, updated_at=excluded.updated_at"#,
                params![&ip, &ip, &t],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await??;
        
        Ok(())
    }

    pub async fn upsert_service(
        &self,
        ip: &str,
        port: u16,
        proto: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let ts = Utc::now();
        let t = ts.to_rfc3339();
        
        // Use spawn_blocking to run database operations on a blocking thread
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let proto = proto.to_string();
        let reason = reason.map(|r| r.to_string());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();

            // Ensure host row exists (id = ip convention here for simplicity)
            conn.execute(
                r#"INSERT INTO hosts(id, ip, first_seen, last_seen, created_at, updated_at, status, tags, port_count, vulnerability_count)
                   VALUES(?1, ?1, ?2, ?2, ?2, ?2, 'unknown', '[]', 0, 0)
                   ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, updated_at=excluded.updated_at"#,
                params![&ip, &t],
            )?;

            let port_id = format!("{}:{}/{}", &ip, port, &proto);
            conn.execute(
                r#"INSERT INTO ports(id, host_id, number, protocol, reason, first_seen, last_seen)
                   VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)
                   ON CONFLICT(host_id, number, protocol)
                   DO UPDATE SET last_seen=excluded.last_seen, reason=COALESCE(excluded.reason, ports.reason)"#,
                params![port_id, &ip, port as i64, &proto, reason, &t],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await??;
        
        Ok(())
    }

    pub async fn get_all_hosts(&self) -> Result<Vec<crate::shared::Host>> {
        let conn = self.conn.clone();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, ip, hostname, mac_address, vendor, os_name, os_family, os_accuracy,
                        status, first_seen, last_seen, created_at, updated_at, port_count, vulnerability_count, notes, tags, scan_progress
                 FROM hosts ORDER BY last_seen DESC",
            )?;
            let iter = stmt.query_map([], |row| {
                let id: String = row.get(0)?;
                let ip: String = row.get(1)?;
                let hostname: Option<String> = row.get(2)?;
                let mac_address: Option<String> = row.get(3)?;
                let vendor: Option<String> = row.get(4)?;
                let os_name: Option<String> = row.get(5)?;
                let os_family: Option<String> = row.get(6)?;
                let os_accuracy: Option<f32> = row.get(7)?;
                let status_s: String = row.get(8)?;
                let _first_seen: String = row.get(9)?;
                let last_seen: String = row.get(10)?;
                let created_at: String = row.get(11)?;
                let updated_at: String = row.get(12)?;
                let port_count: i32 = row.get(13)?;
                let vulnerability_count: i32 = row.get(14)?;
                let notes: Option<String> = row.get(15)?;
                let tags_s: Option<String> = row.get(16)?;
                let scan_progress: Option<f32> = row.get(17)?;

                Ok(crate::shared::Host {
                    id,
                    ip,
                    hostname,
                    mac_address,
                    vendor,
                    os_name,
                    os_family,
                    os_accuracy,
                    status: status_s.parse().unwrap_or(crate::shared::HostStatus::Unknown),
                    last_seen: from_rfc3339(&last_seen),
                    created_at: from_rfc3339(&created_at),
                    updated_at: from_rfc3339(&updated_at),
                    port_count,
                    vulnerability_count,
                    notes,
                    tags: decode_tags(tags_s),
                    scan_progress,
                })
            })?;
            
            let mut hosts = Vec::new();
            for host in iter {
                hosts.push(host?);
            }
            Ok::<Vec<crate::shared::Host>, anyhow::Error>(hosts)
        }).await?
    }

    pub async fn update_host_os(
        &self,
        ip: &str,
        os_name: Option<&str>,
        os_family: Option<&str>,
        os_accuracy: Option<f32>,
    ) -> Result<()> {
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let os_name = os_name.map(|s| s.to_string());
        let os_family = os_family.map(|s| s.to_string());
        let timestamp = Utc::now().to_rfc3339();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                r#"UPDATE hosts SET
                   os_name = COALESCE(?2, os_name),
                   os_family = COALESCE(?3, os_family),
                   os_accuracy = COALESCE(?4, os_accuracy),
                   updated_at = ?5, last_seen = ?5
                   WHERE ip = ?1"#,
                params![&ip, os_name, os_family, os_accuracy, &timestamp],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await?
    }

    pub async fn update_host_info(
        &self,
        ip: &str,
        hostname: Option<&str>,
        mac_address: Option<&str>,
        vendor: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let hostname = hostname.map(|s| s.to_string());
        let mac_address = mac_address.map(|s| s.to_string());
        let vendor = vendor.map(|s| s.to_string());
        let timestamp = Utc::now().to_rfc3339();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                r#"UPDATE hosts SET
                   hostname = COALESCE(?2, hostname),
                   mac_address = COALESCE(?3, mac_address),
                   vendor = COALESCE(?4, vendor),
                   updated_at = ?5, last_seen = ?5
                   WHERE ip = ?1"#,
                params![&ip, hostname, mac_address, vendor, &timestamp],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await?
    }
}
