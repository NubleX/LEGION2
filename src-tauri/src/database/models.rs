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

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::fmt;
use std::str::FromStr;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub os_name: Option<String>,
    pub os_family: Option<String>,
    pub os_accuracy: Option<f32>,
    pub status: HostStatus,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub port_count: i32,
    pub vulnerability_count: i32,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub scan_progress: Option<f32>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
    Scanning,
}

impl fmt::Display for HostStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HostStatus::Up => write!(f, "Up"),
            HostStatus::Down => write!(f, "Down"),
            HostStatus::Unknown => write!(f, "Unknown"),
            HostStatus::Scanning => write!(f, "Scanning"),
        }
    }
}

impl FromStr for HostStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Up" => Ok(HostStatus::Up),
            "Down" => Ok(HostStatus::Down),
            "Unknown" => Ok(HostStatus::Unknown),
            "Scanning" => Ok(HostStatus::Scanning),
            _ => Err(anyhow::anyhow!("Invalid HostStatus: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub total_scans: u32,
    pub active_scans: u32,
    pub completed_scans: u32,
    pub failed_scans: u32,
    pub total_hosts_discovered: u32,
    pub total_ports_found: u32,
    pub total_vulnerabilities: u32,
}