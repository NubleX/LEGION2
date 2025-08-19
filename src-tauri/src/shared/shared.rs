// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
use crate::network::netsniffer;

use anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

// Core observation types - moved from core/types.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

impl fmt::Display for HostStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostStatus::Up => write!(f, "up"),
            HostStatus::Down => write!(f, "down"),
            HostStatus::Unknown => write!(f, "unknown"),
        }
    }
}

impl FromStr for HostStatus {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "up" => Ok(HostStatus::Up),
            "down" => Ok(HostStatus::Down),
            "unknown" => Ok(HostStatus::Unknown),
            other => Err(anyhow::anyhow!("Invalid HostStatus: {}", other)),
        }
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    #[allow(dead_code)] // The as_str() method is a utility function I may need later for string conversions.
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            _ => Err(anyhow::anyhow!("Invalid Protocol: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl PortState {
    #[allow(dead_code)] // The as_str() method is a utility function I may need later for string conversions.
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::Unknown => "unknown",
        }
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::Unknown => write!(f, "unknown"),
        }
    }
}

impl FromStr for PortState {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(PortState::Open),
            "closed" => Ok(PortState::Closed),
            "filtered" => Ok(PortState::Filtered),
            "unknown" => Ok(PortState::Unknown),
            _ => Err(anyhow::anyhow!("Invalid PortState: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
            Severity::Unknown => write!(f, "unknown"),
        }
    }
}

impl FromStr for Severity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            "unknown" => Ok(Severity::Unknown),
            _ => Err(anyhow::anyhow!("Invalid Severity: {}", s)),
        }
    }
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

// This Port struct is for database storage, with fields relevant for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPort {
    pub id: String,
    pub host_id: String,
    pub number: i32,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub confidence: Option<f32>,
    pub cpe: Vec<String>,
    pub discovered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
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

// This Vulnerability struct is for database storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVulnerability {
    pub id: String,
    pub host_id: String,
    pub port_id: Option<String>,
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

// Simple event system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ScanStarted,
    ScanCompleted,
    ScanFailed,
    ScanProgress,
    ScanOutput,
    HostDiscovered,
    ServiceDiscovered,
    Progress,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    pub scan_id: String,
    pub event_type: EventType,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

// Minimal event streamer
pub struct EventStreamer {
    events: std::sync::Arc<tokio::sync::RwLock<Vec<ScanEvent>>>,
}

impl EventStreamer {
    pub fn new() -> Self {
        Self {
            events: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    pub async fn send_event(&self, event: ScanEvent) {
        self.events.write().await.push(event);
    }

    pub async fn get_recent_events(&self, limit: usize) -> Vec<ScanEvent> {
        let events = self.events.read().await;
        if events.len() > limit {
            events[events.len() - limit..].to_vec()
        } else {
            events.clone()
        }
    }
}
