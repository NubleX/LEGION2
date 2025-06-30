pub mod coordinator;
pub mod nmap;
pub mod masscan;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use uuid::Uuid;

// Re-export validation
pub use crate::utils::validation::InputValidator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: Uuid,
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Quick,
    Comprehensive,
    Stealth,
    Custom { options: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub target_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub status: ScanStatus,
    pub open_ports: Vec<Port>,
    pub os_detection: Option<OsDetection>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsDetection {
    pub name: String,
    pub accuracy: f32,
    pub family: String,
    pub vendor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

// Additional types needed by commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub target_id: String,
    pub progress: f32,
    pub current_phase: String,
    pub discovered_hosts: u32,
    pub total_ports_scanned: u32,
    pub open_ports_found: u32,
    pub estimated_time_remaining: Option<u32>,
    pub message: Option<String>,
    pub start_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_scans: u32,
    pub active_scans: u32,
    pub completed_scans: u32,
    pub failed_scans: u32,
    pub total_hosts_discovered: u32,
    pub total_ports_discovered: u32,
    pub total_vulnerabilities: u32,
    pub scan_time_total: u32,
    pub avg_scan_duration: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub status: String,
    pub discovered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

// Coordinator types
pub use coordinator::ScanCoordinator;