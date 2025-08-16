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