// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::time::Duration;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: String,
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub ports: Option<Vec<u16>>,
    pub scan_type: ScanType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub target_ip: String,
    pub scan_type: ScanType,
    pub port_range: Option<String>,
    pub max_concurrent: Option<usize>,
    pub timeout: Option<u64>,
    pub stealth_mode: Option<bool>,
    pub os_detection: Option<bool>,
    pub service_detection: Option<bool>,
    pub vulnerability_scan: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub scan_type: ScanType,
    pub timing: ScanTiming,
    pub port_range: PortRange,
    pub max_concurrent: usize,
    pub timeout: Duration,
    pub stealth_mode: bool,
    pub os_detection: bool,
    pub service_detection: bool,
    pub vulnerability_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Discovery,
    PortScan,
    ServiceDetection,
    Vulnerability,
    Comprehensive,
    Quick,
    Stealth,
    Custom { options: String },
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScanType::Discovery => write!(f, "Discovery"),
            ScanType::PortScan => write!(f, "PortScan"),
            ScanType::ServiceDetection => write!(f, "ServiceDetection"),
            ScanType::Vulnerability => write!(f, "Vulnerability"),
            ScanType::Comprehensive => write!(f, "Comprehensive"),
            ScanType::Quick => write!(f, "Quick"),
            ScanType::Stealth => write!(f, "Stealth"),
            ScanType::Custom { options } => write!(f, "Custom ({})", options),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTiming {
    Paranoid,  // T0
    Sneaky,    // T1
    Polite,    // T2
    Normal,    // T3
    Aggressive, // T4
    Insane,    // T5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
    pub top_ports: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub progress: f32,
    pub current_target: Option<String>,
    pub hosts_discovered: u32,
    pub ports_found: u32,
    pub vulnerabilities: u32,
    pub elapsed_time: u64,
    pub estimated_remaining: Option<u64>,
    pub message: Option<String>,
    pub start_time: DateTime<Utc>,
    pub current_phase: String,
}

use crate::shared::{ScanPort, ScanVulnerability};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub target_id: String,
    pub status: ScanStatus,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration: Option<u64>,
    pub open_ports: Vec<ScanPort>,
    pub os_detection: Option<OSDetection>,
    pub vulnerabilities: Vec<ScanVulnerability>,
    pub scan_type: String,
    pub error_message: Option<String>,
    pub raw_output: Option<String>,
    pub command_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSDetection {
    pub name: String,
    pub family: String,
    pub generation: Option<String>,
    pub vendor: Option<String>,
    pub accuracy: f32,
    pub fingerprint: Option<String>,
    pub cpe: Vec<String>,
}