use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::fmt;
use anyhow;

/// Plan defines what the engine should execute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// The source type (e.g., "masscan", "nmap", "custom")
    pub source_type: String,
    /// Source configuration parameters
    pub source_config: HashMap<String, serde_json::Value>,
    /// List of sink types to use (e.g., ["ui", "db", "file"])
    pub sink_types: Vec<String>,
    /// Optional sink configurations
    pub sink_configs: HashMap<String, HashMap<String, serde_json::Value>>,
}

impl Plan {
    /// Create a masscan plan
    pub fn masscan(targets: String, ports: String, extra_args: Vec<String>) -> Self {
        let mut source_config = HashMap::new();
        source_config.insert("targets".to_string(), serde_json::Value::String(targets));
        source_config.insert("ports".to_string(), serde_json::Value::String(ports));
        source_config.insert("extra_args".to_string(), serde_json::Value::Array(
            extra_args.into_iter().map(serde_json::Value::String).collect()
        ));

        Self {
            source_type: "masscan".to_string(),
            source_config,
            sink_types: vec!["ui".to_string(), "db".to_string()],
            sink_configs: HashMap::new(),
        }
    }

    /// Create an nmap plan  
    pub fn nmap(target: String, args: Vec<String>) -> Self {
        let mut source_config = HashMap::new();
        source_config.insert("target".to_string(), serde_json::Value::String(target));
        source_config.insert("args".to_string(), serde_json::Value::Array(
            args.into_iter().map(serde_json::Value::String).collect()
        ));

        Self {
            source_type: "nmap".to_string(),
            source_config,
            sink_types: vec!["ui".to_string(), "db".to_string()],
            sink_configs: HashMap::new(),
        }
    }

    /// Add a sink configuration
    pub fn with_sink_config(mut self, sink_type: String, config: HashMap<String, serde_json::Value>) -> Self {
        self.sink_configs.insert(sink_type, config);
        self
    }

    /// Add a sink type
    pub fn with_sink(mut self, sink_type: String) -> Self {
        if !self.sink_types.contains(&sink_type) {
            self.sink_types.push(sink_type);
        }
        self
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