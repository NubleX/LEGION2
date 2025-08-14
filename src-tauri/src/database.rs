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
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::sync::Mutex;

// For the comprehensive async facade
use tokio::sync::Mutex as AsyncMutex;

// Types used by DatabaseOperations
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

        CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);
        CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname);
        CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
        CREATE INDEX IF NOT EXISTS idx_ports_num_proto ON ports(number, protocol);
        CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id);
    "#,
    )?;
    Ok(())
}

// ------------- your original simple Db (kept) -------------

pub struct Db {
    pub(crate) conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        ensure_schema(&conn)?; // use the full schema now
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn upsert_host(&self, ip: &str, ts: DateTime<Utc>) -> Result<()> {
        let t = ts.to_rfc3339();
        let conn = self.conn.lock().unwrap();

        // If no row, insert with the extended columns initialized;
        // if exists, just bump last_seen.
        conn.execute(
            r#"INSERT INTO hosts(id, ip, first_seen, last_seen, created_at, updated_at, status, tags, port_count, vulnerability_count)
               VALUES(?1, ?2, ?3, ?3, ?3, ?3, 'unknown', '[]', 0, 0)
               ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, updated_at=excluded.updated_at"#,
            params![ip, ip, &t],
        )?;
        Ok(())
    }

    pub fn upsert_service(
        &self,
        ip: &str,
        port: u16,
        proto: &str,
        reason: Option<&str>,
        ts: DateTime<Utc>,
    ) -> Result<()> {
        let t = ts.to_rfc3339();
        let conn = self.conn.lock().unwrap();

        // Ensure host row exists (id = ip convention here for simplicity)
        conn.execute(
            r#"INSERT INTO hosts(id, ip, first_seen, last_seen, created_at, updated_at, status, tags, port_count, vulnerability_count)
               VALUES(?1, ?1, ?2, ?2, ?2, ?2, 'unknown', '[]', 0, 0)
               ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, updated_at=excluded.updated_at"#,
            params![ip, &t],
        )?;

        let port_id = format!("{ip}:{}/{}", port, proto);
        conn.execute(
            r#"INSERT INTO ports(id, host_id, number, protocol, reason, first_seen, last_seen)
               VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)
               ON CONFLICT(host_id, number, protocol)
               DO UPDATE SET last_seen=excluded.last_seen, reason=COALESCE(excluded.reason, ports.reason)"#,
            params![port_id, ip, port as i64, proto, reason, &t],
        )?;
        Ok(())
    }

    pub fn get_all_hosts(&self) -> Result<Vec<crate::shared::Host>> {
        let conn = self.conn.lock().unwrap();
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
                status: status_s
                    .parse()
                    .unwrap_or(crate::shared::HostStatus::Unknown),
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

        let mut out = Vec::new();
        for h in iter {
            out.push(h?);
        }
        Ok(out)
    }

    pub fn update_host_os(
        &self,
        ip: &str,
        os_name: Option<&str>,
        os_family: Option<&str>,
        os_accuracy: Option<f32>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"UPDATE hosts SET
               os_name = COALESCE(?2, os_name),
               os_family = COALESCE(?3, os_family),
               os_accuracy = COALESCE(?4, os_accuracy),
               updated_at = ?5, last_seen = ?5
               WHERE ip = ?1"#,
            params![ip, os_name, os_family, os_accuracy, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn update_host_info(
        &self,
        ip: &str,
        hostname: Option<&str>,
        mac_address: Option<&str>,
        vendor: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"UPDATE hosts SET
               hostname = COALESCE(?2, hostname),
               mac_address = COALESCE(?3, mac_address),
               vendor = COALESCE(?4, vendor),
               updated_at = ?5, last_seen = ?5
               WHERE ip = ?1"#,
            params![ip, hostname, mac_address, vendor, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
}

// ------------- comprehensive async DatabaseOperations -------------

pub struct DatabaseOperations {
    pub conn: AsyncMutex<Connection>,
}

impl DatabaseOperations {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: AsyncMutex::new(conn),
        }
    }

    pub async fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        ensure_schema(&conn)?;
        Ok(Self::new(conn))
    }

    /// Map a row to Host (single place).
    fn parse_host_row(row: &Row<'_>) -> rusqlite::Result<Host> {
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

        Ok(Host {
            id,
            ip,
            hostname,
            mac_address,
            vendor,
            os_name,
            os_family,
            os_accuracy,
            status: status_s.parse().unwrap_or(HostStatus::Unknown),
            last_seen: from_rfc3339(&last_seen),
            created_at: from_rfc3339(&created_at),
            updated_at: from_rfc3339(&updated_at),
            port_count,
            vulnerability_count,
            notes,
            tags: decode_tags(tags_s),
            scan_progress,
        })
    }

    pub async fn upsert_host(&self, ip: &str, hostname: Option<&str>) -> anyhow::Result<Host> {
        let now = Utc::now();
        let now_s = to_rfc3339(now);

        if let Some(mut h) = self.try_get_host_by_ip(ip).await? {
            let conn = self.conn.lock().await;
            conn.execute(
                r#"UPDATE hosts SET hostname = COALESCE(?2, hostname),
                                  last_seen = ?3,
                                  updated_at = ?3
                   WHERE ip = ?1"#,
                params![ip, hostname, &now_s],
            )?;
            drop(conn);
            h.hostname = hostname.map(|s| s.to_string());
            h.last_seen = now;
            h.updated_at = now;
            Ok(h)
        } else {
            let id = ip.to_string(); // stable id = ip
            let conn = self.conn.lock().await;
            conn.execute(
                r#"INSERT INTO hosts(
                        id, ip, hostname, status,
                        first_seen, last_seen, created_at, updated_at,
                        port_count, vulnerability_count, tags
                    ) VALUES (?1, ?2, ?3, 'unknown', ?4, ?4, ?4, ?4, 0, 0, '[]')"#,
                params![&id, ip, hostname, &now_s],
            )?;
            Ok(Host {
                id,
                ip: ip.to_string(),
                hostname: hostname.map(|s| s.to_string()),
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
                tags: vec![],
                scan_progress: None,
            })
        }
    }

    pub async fn try_get_host_by_ip(&self, ip: &str) -> anyhow::Result<Option<Host>> {
        let conn = self.conn.lock().await;
        conn.query_row(
            r#"SELECT id, ip, hostname, mac_address, vendor, os_name, os_family,
                       os_accuracy, status, first_seen, last_seen, created_at, updated_at,
                       port_count, vulnerability_count, notes, tags, scan_progress
                FROM hosts WHERE ip = ?1"#,
            params![ip],
            Self::parse_host_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub async fn get_host_by_ip(&self, ip: &str) -> anyhow::Result<Host> {
        self.try_get_host_by_ip(ip)
            .await?
            .ok_or_else(|| anyhow::anyhow!("host not found: {ip}"))
    }

    pub async fn get_host_by_id(&self, id: &str) -> anyhow::Result<Host> {
        let conn = self.conn.lock().await;
        conn.query_row(
            r#"SELECT id, ip, hostname, mac_address, vendor, os_name, os_family,
                       os_accuracy, status, first_seen, last_seen, created_at, updated_at,
                       port_count, vulnerability_count, notes, tags, scan_progress
                FROM hosts WHERE id = ?1"#,
            params![id],
            Self::parse_host_row,
        )
        .map_err(Into::into)
    }

    pub async fn get_hosts(&self, limit: i64, offset: i64) -> anyhow::Result<Vec<Host>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            r#"SELECT id, ip, hostname, mac_address, vendor, os_name, os_family,
                       os_accuracy, status, first_seen, last_seen, created_at, updated_at,
                       port_count, vulnerability_count, notes, tags, scan_progress
                FROM hosts ORDER BY last_seen DESC LIMIT ?1 OFFSET ?2"#,
        )?;
        let rows = stmt.query_map(params![limit, offset], Self::parse_host_row)?;
        let mut out = Vec::with_capacity(64);
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub async fn update_host_status(&self, id: &str, status: HostStatus) -> anyhow::Result<()> {
        let now = to_rfc3339(Utc::now());
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE hosts SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status.to_string(), &now, id],
        )?;
        Ok(())
    }

    pub async fn update_host_os(
        &self,
        id: &str,
        os_name: Option<&str>,
        os_family: Option<&str>,
        os_accuracy: Option<f32>,
    ) -> anyhow::Result<()> {
        let now = to_rfc3339(Utc::now());
        let conn = self.conn.lock().await;
        conn.execute(
            r#"UPDATE hosts SET os_name = COALESCE(?1, os_name),
                              os_family = COALESCE(?2, os_family),
                              os_accuracy = COALESCE(?3, os_accuracy),
                              updated_at = ?4
               WHERE id = ?5"#,
            params![os_name, os_family, os_accuracy, &now, id],
        )?;
        Ok(())
    }

    pub async fn update_host_notes(&self, id: &str, notes: Option<String>) -> anyhow::Result<()> {
        let now = to_rfc3339(Utc::now());
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE hosts SET notes = ?1, updated_at = ?2 WHERE id = ?3",
            params![notes, &now, id],
        )?;
        Ok(())
    }

    pub async fn update_host_tags(&self, id: &str, tags: Vec<String>) -> anyhow::Result<()> {
        let tags_json = encode_tags(&tags);
        let now = to_rfc3339(Utc::now());
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE hosts SET tags = ?1, updated_at = ?2 WHERE id = ?3",
            params![tags_json, &now, id],
        )?;
        Ok(())
    }

    pub async fn delete_host(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM hosts WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub async fn search_hosts_paged(
        &self,
        term: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Host>> {
        let conn = self.conn.lock().await;
        if let Some(t) = term {
            let like = format!("%{}%", t);
            let mut stmt = conn.prepare(
                r#"SELECT id, ip, hostname, mac_address, vendor, os_name, os_family,
                           os_accuracy, status, first_seen, last_seen, created_at, updated_at,
                           port_count, vulnerability_count, notes, tags, scan_progress
                    FROM hosts
                    WHERE ip LIKE ?1
                       OR COALESCE(hostname,'') LIKE ?1
                       OR COALESCE(os_name,'') LIKE ?1
                       OR COALESCE(notes,'') LIKE ?1
                    ORDER BY last_seen DESC LIMIT ?2 OFFSET ?3"#,
            )?;
            let rows = stmt.query_map(params![like, limit, offset], Self::parse_host_row)?;
            let mut out = Vec::with_capacity(64);
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        } else {
            self.get_hosts(limit, offset).await
        }
    }

    pub async fn batch_upsert_hosts(&self, hosts: &[Host]) -> anyhow::Result<usize> {
        let now = to_rfc3339(Utc::now());
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        let mut n = 0usize;
        {
            let mut insert_stmt = tx.prepare(
                r#"INSERT INTO hosts(
                        id, ip, hostname, status,
                        first_seen, last_seen, created_at, updated_at,
                        port_count, vulnerability_count, notes, tags
                    )
                    VALUES(?1, ?2, ?3, COALESCE(?4,'unknown'), ?5, ?5, ?5, ?5,
                           COALESCE(?6,0), COALESCE(?7,0), ?8, ?9)
                    ON CONFLICT(ip) DO UPDATE SET
                        hostname = COALESCE(excluded.hostname, hosts.hostname),
                        status   = COALESCE(excluded.status, hosts.status),
                        last_seen = excluded.last_seen,
                        updated_at = excluded.updated_at,
                        notes    = COALESCE(excluded.notes, hosts.notes),
                        tags     = COALESCE(excluded.tags, hosts.tags)
                "#,
            )?;
            for h in hosts {
                insert_stmt.execute(params![
                    &h.id,
                    &h.ip,
                    &h.hostname,
                    h.status.to_string(),
                    &now,
                    h.port_count,
                    h.vulnerability_count,
                    &h.notes,
                    encode_tags(&h.tags),
                ])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    // ---- ports (minimal) ----

    pub async fn add_port(
        &self,
        host_id: &str,
        number: u16,
        protocol: &str,
        state: Option<&str>,
        service_name: Option<&str>,
        product: Option<&str>,
        version: Option<&str>,
        reason: Option<&str>,
        banner: Option<&str>,
    ) -> anyhow::Result<()> {
        let now = to_rfc3339(Utc::now());
        let id = format!("{host_id}:{number}/{protocol}");
        let conn = self.conn.lock().await;
        conn.execute(
            r#"INSERT INTO ports(id, host_id, number, protocol, state, service_name, product, version, reason, banner, first_seen, last_seen)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)
               ON CONFLICT(host_id, number, protocol) DO UPDATE SET
                 state        = COALESCE(excluded.state,        ports.state),
                 service_name = COALESCE(excluded.service_name, ports.service_name),
                 product      = COALESCE(excluded.product,      ports.product),
                 version      = COALESCE(excluded.version,      ports.version),
                 reason       = COALESCE(excluded.reason,       ports.reason),
                 banner       = COALESCE(excluded.banner,       ports.banner),
                 last_seen    = excluded.last_seen"#,
            params![&id, host_id, number as i64, protocol, state, service_name, product, version, reason, banner, &now],
        )?;
        drop(conn);
        self.update_host_port_count(host_id).await?;
        Ok(())
    }

    pub async fn batch_insert_ports(
        &self,
        host_id: &str,
        ports: &[(u16, &str, Option<&str>)],
    ) -> anyhow::Result<usize> {
        let now = to_rfc3339(Utc::now());
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        let mut n = 0usize;
        {
            let mut stmt = tx.prepare(
                r#"INSERT INTO ports(id, host_id, number, protocol, service_name, first_seen, last_seen)
                   VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)
                   ON CONFLICT(host_id, number, protocol) DO UPDATE SET
                     service_name = COALESCE(excluded.service_name, ports.service_name),
                     last_seen    = excluded.last_seen"#,
            )?;
            for (num, proto, svc) in ports {
                let id = format!("{host_id}:{num}/{proto}");
                stmt.execute(params![id, host_id, *num as i64, *proto, *svc, &now])?;
                n += 1;
            }
        }
        tx.commit()?;
        drop(conn);
        self.update_host_port_count(host_id).await?;
        Ok(n)
    }

    async fn update_host_port_count(&self, host_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ports WHERE host_id = ?1",
            params![host_id],
            |r| r.get(0),
        )?;
        let now = to_rfc3339(Utc::now());
        conn.execute(
            "UPDATE hosts SET port_count = ?1, updated_at = ?2 WHERE id = ?3",
            params![count as i64, &now, host_id],
        )?;
        Ok(())
    }

    // ---- vulns (minimal) ----

    pub async fn add_vulnerability(
        &self,
        host_id: &str,
        port_id: Option<&str>,
        name: &str,
        severity: &str,
        description: Option<&str>,
        cve: Option<&str>,
        cvss_score: Option<f32>,
    ) -> anyhow::Result<()> {
        let now = to_rfc3339(Utc::now());
        let id = format!("vuln:{}:{}:{}", host_id, port_id.unwrap_or("-"), name);
        let conn = self.conn.lock().await;
        conn.execute(
            r#"INSERT INTO vulnerabilities(id, host_id, port_id, name, severity, description, cve, cvss_score, discovered_at, last_seen)
               VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
               ON CONFLICT(id) DO UPDATE SET
                 severity    = excluded.severity,
                 description = COALESCE(excluded.description, vulnerabilities.description),
                 cve         = COALESCE(excluded.cve,         vulnerabilities.cve),
                 cvss_score  = COALESCE(excluded.cvss_score,  vulnerabilities.cvss_score),
                 last_seen   = excluded.last_seen"#,
            params![id, host_id, port_id, name, severity, description, cve, cvss_score, &now],
        )?;
        drop(conn);
        self.update_host_vulnerability_count(host_id).await?;
        Ok(())
    }

    pub async fn batch_insert_vulnerabilities(
        &self,
        host_id: &str,
        vulns: &[(String, String, Option<String>, Option<f32>)],
    ) -> anyhow::Result<usize> {
        let now = to_rfc3339(Utc::now());
        let mut conn = self.conn.lock().await;
        let tx = conn.transaction()?;
        let mut n = 0usize;
        {
            let mut stmt = tx.prepare(
                r#"INSERT INTO vulnerabilities(id, host_id, name, severity, cve, cvss_score, discovered_at, last_seen)
                   VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                   ON CONFLICT(id) DO UPDATE SET
                     severity   = excluded.severity,
                     cve        = COALESCE(excluded.cve, vulnerabilities.cve),
                     cvss_score = COALESCE(excluded.cvss_score, vulnerabilities.cvss_score),
                     last_seen  = excluded.last_seen"#,
            )?;
            for (name, severity, cve, cvss) in vulns {
                let id = format!("vuln:{}:{}", host_id, name);
                stmt.execute(params![id, host_id, name, severity, cve, cvss, &now])?;
                n += 1;
            }
        }
        tx.commit()?;
        drop(conn);
        self.update_host_vulnerability_count(host_id).await?;
        Ok(n)
    }

    async fn update_host_vulnerability_count(&self, host_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE host_id = ?1",
            params![host_id],
            |r| r.get(0),
        )?;
        let now = to_rfc3339(Utc::now());
        conn.execute(
            "UPDATE hosts SET vulnerability_count = ?1, updated_at = ?2 WHERE id = ?3",
            params![count as i64, &now, host_id],
        )?;
        Ok(())
    }
}
