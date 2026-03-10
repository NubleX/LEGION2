// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::Mutex;
use serde_json;

use crate::offensive::CVE::{CVE, Severity};

fn to_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

fn from_rfc3339(s: &str) -> DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn ensure_cve_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS cves (
            id                  TEXT PRIMARY KEY,
            name                TEXT NOT NULL UNIQUE,
            product             TEXT NOT NULL,
            version             TEXT NOT NULL,
            url                 TEXT NOT NULL,
            source              TEXT NOT NULL,
            severity            TEXT NOT NULL,
            exploit_id          TEXT,
            exploit             TEXT,
            exploit_url         TEXT,
            description         TEXT,
            cvss_score          REAL,
            published_date      TEXT,
            last_modified_date  TEXT,
            cve_references      TEXT,  -- JSON array
            cwe                 TEXT,   -- JSON array
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product);
        CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
        CREATE INDEX IF NOT EXISTS idx_cves_name ON cves(name);
        CREATE INDEX IF NOT EXISTS idx_cves_updated ON cves(updated_at);
    "#,
    )?;
    Ok(())
}

/// CVE Database for persistent storage
pub struct CveDb {
    conn: Arc<Mutex<Connection>>,
}

impl CveDb {
    pub fn open(path: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(path.parent().unwrap())?;
        let conn = Connection::open(path)?;
        ensure_cve_schema(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn get_cve_db_path() -> PathBuf {
        // Use app data directory for CVE database
        let app_data_dir = std::env::current_exe()
            .unwrap_or_else(|_| std::env::current_dir().unwrap().join("legion2"))
            .parent()
            .unwrap()
            .join(".legion2_data");
        app_data_dir.join("cve.db")
    }

    pub fn new() -> Result<Self> {
        let path = Self::get_cve_db_path();
        Self::open(path)
    }

    pub async fn add_cve(&self, cve: &CVE) -> Result<()> {
        let conn = self.conn.clone();
        let cve_clone = cve.clone();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let timestamp = to_rfc3339(Utc::now());
            
            let references_json = serde_json::to_string(&cve_clone.references).unwrap_or_else(|_| "[]".to_string());
            let cwe_json = serde_json::to_string(&cve_clone.cwe).unwrap_or_else(|_| "[]".to_string());
            
            let published_date = cve_clone.published_date.map(to_rfc3339);
            let last_modified_date = cve_clone.last_modified_date.map(to_rfc3339);
            
            conn.execute(
                r#"INSERT INTO cves (
                    id, name, product, version, url, source, severity, exploit_id, exploit, exploit_url,
                    description, cvss_score, published_date, last_modified_date, cve_references, cwe,
                    created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?17)
                ON CONFLICT(name) DO UPDATE SET
                    product = excluded.product,
                    version = excluded.version,
                    url = excluded.url,
                    source = excluded.source,
                    severity = excluded.severity,
                    exploit_id = excluded.exploit_id,
                    exploit = excluded.exploit,
                    exploit_url = excluded.exploit_url,
                    description = excluded.description,
                    cvss_score = excluded.cvss_score,
                    published_date = excluded.published_date,
                    last_modified_date = excluded.last_modified_date,
                    cve_references = excluded.cve_references,
                    cwe = excluded.cwe,
                    updated_at = excluded.updated_at"#,
                params![
                    cve_clone.name,
                    cve_clone.name,
                    cve_clone.product,
                    cve_clone.version,
                    cve_clone.url,
                    cve_clone.source,
                    format!("{:?}", cve_clone.severity).to_lowercase(),
                    cve_clone.exploit_id,
                    cve_clone.exploit,
                    cve_clone.exploit_url,
                    cve_clone.description,
                    cve_clone.cvss_score,
                    published_date,
                    last_modified_date,
                    references_json,
                    cwe_json,
                    timestamp,
                ],
            )?;
            Ok::<(), anyhow::Error>(())
        }).await??;
        Ok(())
    }

    pub async fn get_cve(&self, cve_id: &str) -> Result<Option<CVE>> {
        let conn = self.conn.clone();
        let cve_id = cve_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let mut stmt = conn.prepare(
                r#"SELECT name, product, version, url, source, severity, exploit_id, exploit, exploit_url,
                          description, cvss_score, published_date, last_modified_date, cve_references, cwe
                   FROM cves WHERE name = ?1"#,
            )?;
            
            let result = stmt.query_row([&cve_id], |row| {
                let severity_str: String = row.get(5)?;
                let severity = Severity::from_string(&severity_str);
                
                let references_json: String = row.get(13)?;
                let references: Vec<String> = serde_json::from_str(&references_json).unwrap_or_default();
                
                let cwe_json: String = row.get(14)?;
                let cwe: Vec<String> = serde_json::from_str(&cwe_json).unwrap_or_default();
                
                Ok(CVE {
                    name: row.get(0)?,
                    product: row.get(1)?,
                    version: row.get(2)?,
                    url: row.get(3)?,
                    source: row.get(4)?,
                    severity,
                    exploit_id: row.get(6)?,
                    exploit: row.get(7)?,
                    exploit_url: row.get(8)?,
                    description: row.get(9)?,
                    cvss_score: row.get(10)?,
                    published_date: row.get::<_, Option<String>>(11)?.map(|s| from_rfc3339(&s)),
                    last_modified_date: row.get::<_, Option<String>>(12)?.map(|s| from_rfc3339(&s)),
                    references,
                    cwe,
                })
            }).optional()?;
            
            Ok::<Option<CVE>, anyhow::Error>(result)
        }).await?
    }

    pub async fn search_by_product(&self, product: &str) -> Result<Vec<CVE>> {
        let conn = self.conn.clone();
        let product = product.to_lowercase();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let mut stmt = conn.prepare(
                r#"SELECT name, product, version, url, source, severity, exploit_id, exploit, exploit_url,
                          description, cvss_score, published_date, last_modified_date, cve_references, cwe
                   FROM cves WHERE LOWER(product) LIKE ?1"#,
            )?;
            
            let pattern = format!("%{}%", product);
            let rows = stmt.query_map([&pattern], |row| {
                let severity_str: String = row.get(5)?;
                let severity = Severity::from_string(&severity_str);
                
                let references_json: String = row.get(13)?;
                let references: Vec<String> = serde_json::from_str(&references_json).unwrap_or_default();
                
                let cwe_json: String = row.get(14)?;
                let cwe: Vec<String> = serde_json::from_str(&cwe_json).unwrap_or_default();
                
                Ok(CVE {
                    name: row.get(0)?,
                    product: row.get(1)?,
                    version: row.get(2)?,
                    url: row.get(3)?,
                    source: row.get(4)?,
                    severity,
                    exploit_id: row.get(6)?,
                    exploit: row.get(7)?,
                    exploit_url: row.get(8)?,
                    description: row.get(9)?,
                    cvss_score: row.get(10)?,
                    published_date: row.get::<_, Option<String>>(11)?.map(|s| from_rfc3339(&s)),
                    last_modified_date: row.get::<_, Option<String>>(12)?.map(|s| from_rfc3339(&s)),
                    references,
                    cwe,
                })
            })?;
            
            let mut cves = Vec::new();
            for cve in rows {
                cves.push(cve?);
            }
            Ok::<Vec<CVE>, anyhow::Error>(cves)
        }).await?
    }

    pub async fn count(&self) -> Result<usize> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM cves", [], |row| row.get(0))?;
            Ok::<usize, anyhow::Error>(count as usize)
        }).await?
    }
}

