use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Severity levels for findings and vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium, 
    High,
    Critical,
}

/// Confidence levels for analysis results
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum Confidence {
    Low(f32),    // 0.0-0.4
    Medium(f32), // 0.4-0.7
    High(f32),   // 0.7-1.0
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
    Filtered,
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
    pub fn value(&self) -> f32 {
        match self {
            Confidence::Low(v) => *v,
            Confidence::Medium(v) => *v,
            Confidence::High(v) => *v,
        }
    }

    pub fn from_score(score: f32) -> Self {
        match score {
            s if s < 0.4 => Confidence::Low(s),
            s if s < 0.7 => Confidence::Medium(s), 
            s => Confidence::High(s),
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
            confidence: Confidence::Low(0.0),
            host,
            port: None,
            service: None,
            evidence: HashMap::new(),
            created_at: Utc::now(),
            tags: Vec::new(),
        }
    }
}