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
use sha2::{Sha256, Digest};
use hex;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use rand::Rng;

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

struct EncryptionManager {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for EncryptionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionManager")
            .field("cipher", &"<encrypted>")
            .finish()
    }
}

impl EncryptionManager {
    fn new() -> Self {
        let key = Self::generate_key();
        let cipher = Aes256Gcm::new(&key);
        Self { cipher }
    }
    
    fn generate_key() -> Key<Aes256Gcm> {
        // Generate a deterministic key based on system info + app constants
        let mut hasher = Sha256::new();
        hasher.update(b"LEGION2_PENTESTING_TOOL_2025_ENCRYPTION_KEY");
        
        // Add system-specific entropy
        if let Ok(hostname) = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
            hasher.update(hostname.as_bytes());
        }
        if let Ok(user) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
            hasher.update(user.as_bytes());
        }
        
        // Add current exe path for additional entropy
        if let Ok(exe) = std::env::current_exe() {
            if let Some(path_str) = exe.to_str() {
                hasher.update(path_str.as_bytes());
            }
        }
        
        let hash = hasher.finalize();
        *Key::<Aes256Gcm>::from_slice(&hash)
    }
    
    fn encrypt(&self, data: &str) -> Result<String> {
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = self.cipher.encrypt(nonce, data.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        // Combine nonce + ciphertext and encode as hex
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(hex::encode(result))
    }
    
    fn decrypt(&self, encrypted_hex: &str) -> Result<String> {
        let data = hex::decode(encrypted_hex)
            .map_err(|e| anyhow::anyhow!("Invalid hex data: {}", e))?;
        
        if data.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted data length"));
        }
        
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted data: {}", e))
    }
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS hosts (
            id              TEXT PRIMARY KEY,
            ip_encrypted    TEXT UNIQUE NOT NULL,  -- Encrypted IP
            hostname        TEXT,                  -- Encrypted hostname
            mac_address     TEXT,                  -- Encrypted MAC
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
            notes           TEXT,                  -- Encrypted notes
            tags            TEXT,
            scan_progress   REAL
        );

        CREATE TABLE IF NOT EXISTS ports (
            id           TEXT PRIMARY KEY,
            host_id      TEXT NOT NULL,
            number       INTEGER NOT NULL,
            protocol     TEXT NOT NULL,
            state        TEXT,
            service_name TEXT,                     -- Encrypted service info
            product      TEXT,                     -- Encrypted product info
            version      TEXT,                     -- Encrypted version info
            reason       TEXT,
            banner       TEXT,                     -- Encrypted banner
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
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_ip_encrypted ON hosts(ip_encrypted)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_ports_num_proto ON ports(number, protocol)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id)", []);

    Ok(())
}

// ------------- your original simple Db (kept) -------------

#[derive(Debug)]
pub struct Db {
    pub(crate) conn: Arc<Mutex<Connection>>,
    encryption: EncryptionManager,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        ensure_schema(&conn)?; // use the full schema now
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            encryption: EncryptionManager::new(),
        })
    }

    pub async fn upsert_host(&self, ip: &str, hostname: Option<&str>, status: Option<&str>) -> Result<()> {
        let ts = Utc::now();
        let t = to_rfc3339(ts);
        
        // Encrypt sensitive data
        let ip_encrypted = self.encryption.encrypt(ip)?;
        let hostname_encrypted = if let Some(h) = hostname {
            Some(self.encryption.encrypt(h)?)
        } else {
            None
        };
        
        // Use spawn_blocking to run database operations on a blocking thread
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let status = status.map(|s| s.to_string());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            
            // If no row, insert with the extended columns initialized;
            // if exists, update last_seen and status if provided.
            let host_status = status.as_deref().unwrap_or("unknown");
            conn.execute(
                r#"INSERT INTO hosts(id, ip_encrypted, hostname, first_seen, last_seen, created_at, updated_at, status, tags, port_count, vulnerability_count)
                   VALUES(?1, ?2, ?3, ?4, ?4, ?4, ?4, ?5, '[]', 0, 0)
                   ON CONFLICT(ip_encrypted) DO UPDATE SET last_seen=excluded.last_seen, updated_at=excluded.updated_at, hostname=COALESCE(excluded.hostname, hostname), status=excluded.status"#,
                params![&ip, &ip_encrypted, hostname_encrypted, &t, host_status],
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
        state: Option<&str>,
    ) -> Result<()> {
        // For backward compatibility, just call the enhanced version
        self.upsert_service_detailed(ip, port, proto, state, None, None, None).await
    }

    pub async fn upsert_service_detailed(
        &self,
        ip: &str,
        port: u16,
        proto: &str,
        state: Option<&str>,
        service: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Result<()> {
        let ts = Utc::now();
        let t = to_rfc3339(ts);
        
        // Encrypt sensitive data
        let ip_encrypted = self.encryption.encrypt(ip)?;
        
        // Use spawn_blocking to run database operations on a blocking thread
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let proto = proto.to_string();
        let state = state.map(|s| s.to_string());
        let service = service.map(|s| s.to_string());
        let version = version.map(|s| s.to_string());
        let banner = banner.map(|s| s.to_string());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();

            // Ensure host row exists, but mark as 'down' by default until proven up
            // This prevents phantom hosts from appearing as 'up' in the UI
            conn.execute(
                r#"INSERT INTO hosts(id, ip, first_seen, last_seen, created_at, updated_at, status, port_count, vulnerability_count)
                   VALUES(?1, ?2, ?3, ?3, ?3, ?3, 'down', 0, 0)
                   ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, updated_at=excluded.updated_at"#,
                params![&ip, &ip, &t],
            )?;

            let port_id = format!("{}:{}/{}", &ip, port, &proto);
            conn.execute(
                r#"INSERT INTO ports(id, host_id, number, protocol, state, service, version, banner, created_at)
                   VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                   ON CONFLICT(id)
                   DO UPDATE SET 
                       state=COALESCE(excluded.state, ports.state),
                       service=COALESCE(excluded.service, ports.service),
                       version=COALESCE(excluded.version, ports.version),
                       banner=COALESCE(excluded.banner, ports.banner)"#,
                params![port_id, &ip, port as i64, &proto, state, service, version, banner, &t],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await??;
        
        Ok(())
    }

    pub async fn get_all_hosts(&self) -> Result<Vec<crate::shared::Host>> {
        let conn = self.conn.clone();
        let encryption = EncryptionManager::new(); // Create new instance for decryption
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, ip_encrypted, hostname, mac_address, vendor, os_name, os_family, os_accuracy,
                        status, first_seen, last_seen, created_at, updated_at, port_count, vulnerability_count, notes, tags, scan_progress
                 FROM hosts ORDER BY last_seen DESC",
            )?;
            let iter = stmt.query_map([], |row| {
                let id: String = row.get(0)?;
                let ip_encrypted: String = row.get(1)?;
                let hostname_encrypted: Option<String> = row.get(2)?;
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
                let notes_encrypted: Option<String> = row.get(15)?;
                let tags_s: Option<String> = row.get(16)?;
                let scan_progress: Option<f32> = row.get(17)?;

                // Decrypt sensitive fields
                let ip = encryption.decrypt(&ip_encrypted).unwrap_or_else(|_| "DECRYPTION_ERROR".to_string());
                let hostname = if let Some(h_enc) = hostname_encrypted {
                    encryption.decrypt(&h_enc).ok()
                } else {
                    None
                };
                let notes = if let Some(n_enc) = notes_encrypted {
                    encryption.decrypt(&n_enc).ok()
                } else {
                    None
                };

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

    pub async fn get_host_ports(&self, host_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.clone();
        let host_id = host_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT number, protocol, state, service FROM ports WHERE host_id = ? ORDER BY number",
            )?;
            let rows = stmt.query_map([host_id], |row| {
                let number: i32 = row.get(0)?;
                let protocol: String = row.get(1)?;
                let state: Option<String> = row.get(2)?;
                let service: Option<String> = row.get(3)?;
                Ok(format!("{}/{} {} {}", 
                    number, 
                    protocol, 
                    state.unwrap_or_else(|| "unknown".to_string()),
                    service.unwrap_or_else(|| "".to_string())
                ))
            })?;
            
            let mut ports = Vec::new();
            for port in rows {
                ports.push(port?);
            }
            Ok(ports)
        }).await?
    }

    pub async fn get_host_ports_detailed(&self, host_id: &str) -> Result<Vec<crate::commands::host_commands::PortInfo>> {
        let conn = self.conn.clone();
        let host_id = host_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT number, protocol, state, service, version, banner FROM ports WHERE host_id = ? ORDER BY number",
            )?;
            let rows = stmt.query_map([host_id], |row| {
                let number: i32 = row.get(0)?;
                let protocol: String = row.get(1)?;
                let state: String = row.get(2)?;
                let service: Option<String> = row.get(3)?;
                let version: Option<String> = row.get(4)?;
                let banner: Option<String> = row.get(5)?;
                
                Ok(crate::commands::host_commands::PortInfo {
                    number: number as u16,
                    protocol,
                    state,
                    service,
                    version,
                    banner,
                })
            })?;
            
            let mut ports = Vec::new();
            for row in rows {
                ports.push(row?);
            }
            Ok(ports)
        }).await?
    }

    pub async fn update_host_network_info(&self, ip: &str, mac_address: Option<&str>, vendor: Option<&str>) -> Result<()> {
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let mac_address = mac_address.map(|s| s.to_string());
        let vendor = vendor.map(|s| s.to_string());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            
            // Update the host with MAC address and vendor information
            let mut query = "UPDATE hosts SET updated_at = CURRENT_TIMESTAMP".to_string();
            let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            
            if mac_address.is_some() {
                query.push_str(", mac_address = ?");
                params.push(Box::new(mac_address.clone()));
            }
            
            if vendor.is_some() {
                query.push_str(", vendor = ?");
                params.push(Box::new(vendor.clone()));
            }
            
            query.push_str(" WHERE ip = ?");
            params.push(Box::new(ip));
            
            let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            conn.execute(&query, param_refs.as_slice())?;
            
            Ok(())
        }).await?
    }

    pub async fn get_host_vulnerabilities(&self, host_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.clone();
        let host_id = host_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT name, severity, cve FROM vulnerabilities WHERE host_id = ? ORDER BY severity DESC",
            )?;
            let rows = stmt.query_map([host_id], |row| {
                let name: String = row.get(0)?;
                let severity: String = row.get(1)?;
                let cve: Option<String> = row.get(2)?;
                Ok(format!("{} ({}) {}", 
                    name, 
                    severity,
                    cve.unwrap_or_else(|| "".to_string())
                ))
            })?;
            
            let mut vulns = Vec::new();
            for vuln in rows {
                vulns.push(vuln?);
            }
            Ok(vulns)
        }).await?
    }

    pub async fn delete_host(&self, host_id: &str) -> Result<()> {
        let conn = self.conn.clone();
        let host_id = host_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute("DELETE FROM hosts WHERE id = ?", [host_id])?;
            Ok(())
        }).await?
    }

    pub async fn update_host_tags(&self, host_id: &str, tags: &[String]) -> Result<()> {
        let conn = self.conn.clone();
        let host_id = host_id.to_string();
        let encoded_tags = encode_tags(tags);
        let timestamp = to_rfc3339(Utc::now());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE hosts SET tags = ?, updated_at = ? WHERE id = ?",
                (encoded_tags, timestamp, host_id),
            )?;
            Ok(())
        }).await?
    }

    pub async fn update_host_os(
        &self,
        ip: &str,
        os_name: Option<&str>,
        os_family: Option<&str>,
        os_accuracy: Option<f32>,
    ) -> Result<()> {
        let ip_encrypted = self.encryption.encrypt(ip)?;
        let conn = self.conn.clone();
        let os_name = os_name.map(|s| s.to_string());
        let os_family = os_family.map(|s| s.to_string());
        let timestamp = to_rfc3339(Utc::now());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                r#"UPDATE hosts SET
                   os_name = COALESCE(?2, os_name),
                   os_family = COALESCE(?3, os_family),
                   os_accuracy = COALESCE(?4, os_accuracy),
                   updated_at = ?5, last_seen = ?5
                   WHERE ip_encrypted = ?1"#,
                params![&ip_encrypted, os_name, os_family, os_accuracy, &timestamp],
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
        let ip_encrypted = self.encryption.encrypt(ip)?;
        let hostname_encrypted = if let Some(h) = hostname {
            Some(self.encryption.encrypt(h)?)
        } else {
            None
        };
        let mac_encrypted = if let Some(m) = mac_address {
            Some(self.encryption.encrypt(m)?)
        } else {
            None
        };
        
        let conn = self.conn.clone();
        let vendor = vendor.map(|s| s.to_string());
        let timestamp = to_rfc3339(Utc::now());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                r#"UPDATE hosts SET
                   hostname = COALESCE(?2, hostname),
                   mac_address = COALESCE(?3, mac_address),
                   vendor = COALESCE(?4, vendor),
                   updated_at = ?5, last_seen = ?5
                   WHERE ip_encrypted = ?1"#,
                params![&ip_encrypted, hostname_encrypted, mac_encrypted, vendor, &timestamp],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await?
    }

    /// Increment vulnerability count for a host
    pub async fn increment_host_vulnerability_count(&self, ip: &str) -> Result<()> {
        let ip_encrypted = self.encryption.encrypt(ip)?;
        let conn = self.conn.clone();
        let timestamp = to_rfc3339(Utc::now());
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                r#"UPDATE hosts SET vulnerability_count = vulnerability_count + 1, updated_at = ?2, last_seen = ?2 WHERE ip_encrypted = ?1"#,
                params![&ip_encrypted, &timestamp],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await?
    }
}