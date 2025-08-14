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
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;
use crate::core::registry::Registry;

// Core observation types - moved from core/types.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ObservationKind { 
    Host, 
    Service, 
    Banner, 
    TopologyEdge, 
    Metric, 
    Error 
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub ts: DateTime<Utc>,
    pub kind: ObservationKind,
    pub key: String,                         // e.g. "10.0.0.5:22/tcp"
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