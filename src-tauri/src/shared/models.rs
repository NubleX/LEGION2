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

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use anyhow;

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

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
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
            _ => Err(anyhow::anyhow!("Invalid Severity: {}", s)),
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