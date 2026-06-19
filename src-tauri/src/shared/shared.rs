// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2026 NubleX / Igor Dunaev

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// Re-export commonly used types
pub use crate::shared::types::{PortState, Protocol, Severity};
pub use crate::shared::scan_types::{ScanProgress, ScanStatus, ScanTarget};

// Event types for scan event system (used by masscan.rs)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    ScanStarted,
    ScanCompleted,
    ScanFailed,
    ScanProgress,
    ScanOutput,
    Error,
    ServiceDiscovered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    pub scan_id: String,
    pub event_type: EventType,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

// Core observation types - moved from core/types.rs
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ObservationKind {
    Host,
    Service,
    Banner,
    TopologyEdge,
    Metric,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub ts: DateTime<Utc>,
    pub kind: ObservationKind,
    pub key: String, // e.g. "10.0.0.5:22/tcp"
    pub fields: serde_json::Map<String, serde_json::Value>,
    pub raw: Option<String>,
    pub scan_id: Uuid,
}

pub type ObsStream = futures::stream::BoxStream<'static, Observation>;


/// Classifies network service by port number with security context
pub fn classify_service_by_port(port: u16) -> ServiceInfo {
    match port {
        // Remote Access
        22 => ServiceInfo::new("SSH", "remote_access", Severity::Medium),
        23 => ServiceInfo::new("Telnet", "remote_access", Severity::High), // Insecure
        3389 => ServiceInfo::new("RDP", "remote_desktop", Severity::High),
        // Email Services
        25 => ServiceInfo::new("SMTP", "email", Severity::Medium),
        110 => ServiceInfo::new("POP3", "email", Severity::Medium),
        143 => ServiceInfo::new("IMAP", "email", Severity::Medium),
        465 => ServiceInfo::new("SMTPS", "email_secure", Severity::Low),
        587 => ServiceInfo::new("SMTP (Submission)", "email", Severity::Medium),
        993 => ServiceInfo::new("IMAPS", "email_secure", Severity::Low),
        995 => ServiceInfo::new("POP3S", "email_secure", Severity::Low),
        // Web Services
        80 => ServiceInfo::new("HTTP", "web", Severity::Medium),
        443 => ServiceInfo::new("HTTPS", "web_secure", Severity::Low),
        8080 | 8000 | 8443 | 8888 => {
            ServiceInfo::new("Web Proxy/Alt HTTP", "web", Severity::Medium)
        }
        // DNS
        53 => ServiceInfo::new("DNS", "dns", Severity::Medium),
        // File Transfer
        21 => ServiceInfo::new("FTP", "file_transfer", Severity::High),
        69 => ServiceInfo::new("TFTP", "file_transfer", Severity::High),
        // Databases
        3306 => ServiceInfo::new("MySQL", "database", Severity::High),
        5432 => ServiceInfo::new("PostgreSQL", "database", Severity::High),
        1433 => ServiceInfo::new("MSSQL", "database", Severity::High),
        1521 => ServiceInfo::new("Oracle DB", "database", Severity::High),
        27017 => ServiceInfo::new("MongoDB", "database", Severity::Medium),
        // Cache / Messaging
        6379 => ServiceInfo::new("Redis", "cache", Severity::Medium),
        11211 => ServiceInfo::new("Memcached", "cache", Severity::Medium),
        // System / Infrastructure
        2222 => ServiceInfo::new("DirectAdmin", "admin_panel", Severity::Medium),
        3344 => ServiceInfo::new("PDProxy", "proxy", Severity::Medium),
        5900 => ServiceInfo::new("VNC", "remote_desktop", Severity::High),
        5000 => ServiceInfo::new("UPnP", "discovery", Severity::Medium),
        // Default range for system ports
        _ if port >= 1 && port <= 1023 => {
            ServiceInfo::new("System Service", "system_service", Severity::Medium)
        }
        // Application-specific or dynamic ports
        _ => ServiceInfo::new("Unknown", "application", Severity::Unknown),
    }
}

/// Host information as stored in database and shared with frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub nic_vendor: Option<String>,
    pub nic_model: Option<String>,
    pub os_name: Option<String>,
    pub os_family: Option<String>,
    pub os_accuracy: Option<f32>,
    pub status: String,
    pub last_seen: String,
    pub created_at: String,
    pub updated_at: String,
    pub port_count: i32,
    pub vulnerability_count: i32,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub scan_progress: Option<f32>,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: &'static str,
    pub category: &'static str,
    pub risk: Severity,
}

impl ServiceInfo {
    pub const fn new(name: &'static str, category: &'static str, risk: Severity) -> Self {
        Self {
            name,
            category,
            risk,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub id: String,
    pub output: String,
    pub elements: Option<HashMap<String, String>>,
}

// This Port struct is for scan results, containing detailed information from the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPort {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub confidence: Option<f32>,
    pub cpe: Vec<String>,
    pub scripts: Option<Vec<ScriptResult>>,
}

// This Vulnerability struct is for scan results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanVulnerability {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub cve_id: Option<String>,
    pub reference_links: Vec<String>,
    pub exploitable: bool,
    pub discovered_at: DateTime<Utc>,
    pub verified: bool,
    pub false_positive: bool,
}