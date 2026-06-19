// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

use anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity levels for findings and vulnerabilities
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

impl std::str::FromStr for Severity {
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

/// Network protocols
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Sctp => "sctp",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "sctp" => Ok(Protocol::Sctp),
            _ => Err(anyhow::anyhow!("Invalid Protocol: {}", s)),
        }
    }
}

/// Port states
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for PortState {
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

/// Confidence levels for analysis results (0-100 scale)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct Confidence(pub u8); // 0-100 confidence score

/// Generic finding from analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub host: String,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub evidence: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

/// Vulnerability-specific finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub finding: Finding,
    pub cve_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub exploit_available: bool,
    pub mitigation: Option<String>,
}

/// Network topology representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub hosts: Vec<NetworkHost>,
    pub connections: Vec<NetworkConnection>,
    pub subnets: Vec<NetworkSubnet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub services: Vec<NetworkService>,
    pub status: HostStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkService {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub from_host: String,
    pub to_host: String,
    pub port: u16,
    pub protocol: String,
    pub connection_type: ConnectionType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionType {
    Direct,
    Routed,
    Tunneled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSubnet {
    pub cidr: String,
    pub hosts: Vec<String>,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
    Filtered,
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostStatus::Up => write!(f, "up"),
            HostStatus::Down => write!(f, "down"),
            HostStatus::Unknown => write!(f, "unknown"),
            HostStatus::Filtered => write!(f, "filtered"),
        }
    }
}

impl std::str::FromStr for HostStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "up" => Ok(HostStatus::Up),
            "down" => Ok(HostStatus::Down),
            "unknown" => Ok(HostStatus::Unknown),
            "filtered" => Ok(HostStatus::Filtered),
            _ => Err(anyhow::anyhow!("Invalid HostStatus: {}", s)),
        }
    }
}

/// Attack path through the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<AttackStep>,
    pub difficulty: Difficulty,
    pub impact: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub host: String,
    pub vulnerability: Option<String>,
    pub technique: String,
    pub description: String,
    pub prerequisites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Difficulty {
    Trivial,
    Easy,
    Medium,
    Hard,
    Expert,
}

/// Container for analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub attack_paths: Vec<AttackPath>,
    pub topology: NetworkTopology,
    pub summary: AnalysisSummary,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub total_hosts: u32,
    pub total_services: u32,
    pub vulnerability_count_by_severity: HashMap<Severity, u32>,
    pub top_risks: Vec<Finding>,
    pub recommended_actions: Vec<String>,
}

impl Confidence {
    pub fn new(score: u8) -> Self {
        Confidence(score.min(100))
    }

    pub fn value(&self) -> u8 {
        self.0
    }

    pub fn low() -> Self {
        Confidence(30)
    }

    pub fn medium() -> Self {
        Confidence(70)
    }

    pub fn high() -> Self {
        Confidence(90)
    }

    pub fn as_string(&self) -> &'static str {
        match self.0 {
            0..=40 => "Low",
            41..=70 => "Medium",
            _ => "High", // Covers 71-255, though we cap at 100
        }
    }
}

impl Finding {
    pub fn new(id: String, title: String, host: String) -> Self {
        Self {
            id,
            title,
            description: String::new(),
            severity: Severity::Info,
            confidence: Confidence::low(),
            host,
            port: None,
            service: None,
            evidence: HashMap::new(),
            created_at: Utc::now(),
            tags: Vec::new(),
        }
    }
}
