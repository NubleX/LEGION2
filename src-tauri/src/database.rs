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
use std::sync::Mutex;
use uuid;

pub struct Db { 
    conn: Mutex<Connection>
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        // Small bootstrap schema
        conn.execute_batch(r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                ip TEXT UNIQUE,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY,
                host_ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                proto TEXT NOT NULL,
                reason TEXT,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL,
                UNIQUE(host_ip, port, proto)
            );
        "#)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn upsert_host(&self, ip: &str, ts: DateTime<Utc>) -> Result<()> {
        let t = ts.to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO hosts(ip, first_seen, last_seen) VALUES(?1, ?2, ?3)
               ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen"#,
            params![ip, &t, &t],
        )?;
        Ok(())
    }

    pub fn upsert_service(&self, ip: &str, port: u16, proto: &str, reason: Option<&str>, ts: DateTime<Utc>) -> Result<()> {
        let t = ts.to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO services(host_ip, port, proto, reason, first_seen, last_seen)
               VALUES(?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(host_ip, port, proto)
               DO UPDATE SET last_seen=excluded.last_seen,
                             reason=COALESCE(excluded.reason, services.reason)"#,
            params![ip, port as i64, proto, reason, &t, &t],
        )?;
        Ok(())
    }

    pub fn get_all_hosts(&self) -> Result<Vec<crate::shared::Host>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT ip, first_seen, last_seen FROM hosts")?;
        let host_iter = stmt.query_map([], |row| {
            let ip: String = row.get(0)?;
            let first_seen_str: String = row.get(1)?;
            let last_seen_str: String = row.get(2)?;
            
            let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
                .map_err(|e| rusqlite::Error::InvalidColumnType(0, format!("Invalid date: {}", e).into(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc);
            let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                .map_err(|e| rusqlite::Error::InvalidColumnType(1, format!("Invalid date: {}", e).into(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc);
            
            Ok(crate::shared::Host {
                id: uuid::Uuid::new_v4().to_string(),
                ip,
                hostname: None,
                mac_address: None,
                vendor: None,
                os_name: None,
                os_family: None,
                os_accuracy: None,
                status: crate::shared::HostStatus::Up,
                last_seen,
                created_at: first_seen,
                updated_at: last_seen,
                port_count: 0,
                vulnerability_count: 0,
                notes: None,
                tags: Vec::new(),
                scan_progress: None,
            })
        })?;
        
        let mut hosts = Vec::new();
        for host in host_iter {
            hosts.push(host?);
        }
        Ok(hosts)
    }
}