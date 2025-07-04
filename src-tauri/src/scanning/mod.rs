// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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

pub mod coordinator;
pub mod nmap;
pub mod masscan;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::fmt;

// Re-export important types from submodules
pub use coordinator::{ScanCoordinator, ScanStatistics};
pub use nmap::NmapScanner;


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

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}


// Additional types needed by commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub target_id: String,
    pub progress: f32,
    pub current_phase: String,
    pub discovered_hosts: i32,
    pub total_ports_scanned: i32,
    pub open_ports_found: i32,
    pub estimated_time_remaining: Option<i32>,
    pub message: Option<String>,
    pub start_time: DateTime<Utc>,
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