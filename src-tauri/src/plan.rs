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
use std::collections::HashMap;
use std::str::FromStr;
use std::fmt;
use anyhow;
use uuid::Uuid;

/// Plan defines what the engine should execute - moved from core/types.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub scan_id: Uuid,
    pub targets: String,
    pub ports: String,
    pub rate: Option<u64>,
    pub extra: Vec<String>,
    pub modules: Vec<String>,
    pub source_type: String,
    pub sink_types: Vec<String>,
}

impl Plan {
    /// Create a masscan plan
    pub fn masscan(scan_id: Uuid, targets: String, ports: String, rate: Option<u64>) -> Self {
        Self {
            scan_id,
            targets,
            ports,
            rate,
            extra: vec![],
            modules: vec![],
            source_type: "masscan".to_string(),
            sink_types: vec!["ui".to_string(), "db".to_string()],
        }
    }

    /// Create an nmap plan  
    pub fn nmap(scan_id: Uuid, targets: String, ports: String, extra_args: Vec<String>) -> Self {
        Self {
            scan_id,
            targets,
            ports,
            rate: None,
            extra: extra_args,
            modules: vec![],
            source_type: "nmap".to_string(),
            sink_types: vec!["ui".to_string(), "db".to_string()],
        }
    }

    /// Add extra arguments
    pub fn with_extra_args(mut self, args: Vec<String>) -> Self {
        self.extra.extend(args);
        self
    }

    /// Add modules to the processing pipeline
    pub fn with_modules(mut self, modules: Vec<String>) -> Self {
        self.modules.extend(modules);
        self
    }

    /// Set scan rate (for masscan)
    pub fn with_rate(mut self, rate: u64) -> Self {
        self.rate = Some(rate);
        self
    }

    /// Add a sink type
    pub fn with_sink(mut self, sink_type: String) -> Self {
        if !self.sink_types.contains(&sink_type) {
            self.sink_types.push(sink_type);
        }
        self
    }

    /// Enable OS detection (adds -O flag for nmap)
    pub fn with_os_detection(mut self) -> Self {
        if self.source_type == "nmap" {
            if !self.extra.contains(&"-O".to_string()) {
                self.extra.push("-O".to_string());
            }
        }
        self
    }

    /// Enable comprehensive scan with OS detection, service detection, and aggressive options
    pub fn comprehensive(scan_id: Uuid, targets: String, ports: String) -> Self {
        Self {
            scan_id,
            targets,
            ports,
            rate: None,
            extra: vec!["-sS".to_string(), "-sV".to_string(), "-O".to_string(), "-A".to_string(), "-T4".to_string()],
            modules: vec![],
            source_type: "nmap".to_string(),
            sink_types: vec!["ui".to_string(), "db".to_string()],
        }
    }

    /// Create OS detection specific scan
    pub fn os_detection(scan_id: Uuid, targets: String) -> Self {
        Self {
            scan_id,
            targets,
            ports: "1-1000".to_string(), // Common ports for OS detection
            rate: None,
            extra: vec!["-O".to_string(), "-sS".to_string(), "-T4".to_string()],
            modules: vec![],
            source_type: "nmap".to_string(),
            sink_types: vec!["ui".to_string(), "db".to_string()],
        }
    }
}

// Useful types consolidated from models.rs and shared/models.rs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
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