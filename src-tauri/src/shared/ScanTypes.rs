// Self-import removed - definitions are below
use crate::shared::shared::PortState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;


/// Types of scans that can be performed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Discovery,
    Quick,
    Comprehensive,
    Stealth,
    PivotScan,
    IoTScan,
    NetworkScan,
    JumpHostScan,
    CloudScan,
    BotnetScan,
    SpiderScan,
    WebAppScan,
    VulnerabilityScan,
    PenetrationTest,
    NetworkDiscovery,
    NetworkMapping,
    PortScan,
    ServiceDetection,
    OsDetection,
    HoneypotScan,
    VulnerabilityAssessment,
    Custom { options: String },
}

/// Target specification for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: String,
    pub ip: String,
    pub scan_type: ScanType,
    pub ports: Option<Vec<u16>>,
    pub port_ranges: Option<Vec<PortRange>>,
    pub protocols: Vec<Protocol>,
    pub options: HashMap<String, serde_json::Value>,
    pub custom_args: Vec<String>,
}

/// Port range specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

/// Network protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

/// Current status of a scan
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed(String),
    Cancelled,
    Paused,
}

/// Progress information for a running scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: ScanStatus,
    pub percentage: f32,
    pub stage: String,
    pub targets_completed: usize,
    pub targets_total: usize,
    pub hosts_found: usize,
    pub services_found: usize,
    pub eta_seconds: Option<u64>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub rate: Option<f32>,
    pub details: HashMap<String, serde_json::Value>,
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

/// Configuration for a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub scan_type: ScanType,
    pub targets: Vec<ScanTarget>,
    pub timing: Option<u8>,
    pub max_parallel: Option<usize>,
    pub timeout: Option<u64>,
    pub scanner_options: HashMap<String, serde_json::Value>,
    pub detect_os: bool,
    pub detect_versions: bool,
    pub custom_args: Vec<String>,
    pub port_ranges: Option<Vec<PortRange>>,
    pub protocols: Vec<Protocol>,
    pub rate_limit: Option<u64>,
    pub scan_interface: Option<String>,
    pub scan_source_type: String,
    pub scan_sink_types: Vec<String>,
    pub scan_modules: Vec<String>,
}

/// Result of a completed scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub config: ScanConfig,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u64>,
    pub hosts: Vec<DiscoveredHost>,
    pub services: Vec<DiscoveredService>,
    pub errors: Vec<ScanError>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub scan_type: Option<ScanType>,
    pub error_message: Option<String>,
    pub raw_output: Option<String>,
    pub command_used: Option<String>,
    pub vulnerabilities: Vec<serde_json::Value>,
    pub os_detection: Option<serde_json::Value>,
    pub open_ports: Vec<DiscoveredService>,
    pub closed_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
    pub port_states: HashMap<u16, PortState>,
    pub scan_progress: Option<ScanProgress>,
    pub scan_statistics: Option<ScanStatistics>,
    pub scan_interface: Option<String>,
    pub scan_rate: Option<u64>,
    pub scan_sink_types: Vec<String>,
    pub scan_source_type: String,
    pub scan_modules: Vec<String>,
    pub scan_extra_args: Vec<String>,
    pub scan_port_ranges: Option<Vec<PortRange>>,
    pub scan_target_ips: Vec<IpAddr>,
    pub scan_target_hostnames: Vec<String>,
    pub scan_target_cidrs: Vec<String>,
    pub scan_target_metadata: HashMap<String, serde_json::Value>,
    pub scan_target_options: HashMap<String, serde_json::Value>,
    pub scan_additional_info: HashMap<String, serde_json::Value>,
    pub scan_summary: Option<String>,
    pub scan_raw_output: Option<String>,
    pub scan_custom_args: Vec<String>,
    pub scan_vulnerabilities: Vec<serde_json::Value>,
    pub scan_open_ports: Vec<DiscoveredService>,
    pub scan_discovered_hosts: Vec<DiscoveredHost>,
    pub scan_discovered_services: Vec<DiscoveredService>,
    pub scan_errors: Vec<ScanError>,
    pub scan_start_time: Option<DateTime<Utc>>,
    pub scan_end_time: Option<DateTime<Utc>>,
    pub scan_duration: Option<u64>,
    pub scan_command: Option<String>,
    pub scan_metadata: HashMap<String, serde_json::Value>,
    pub scan_status: ScanStatus,
}

/// A host discovered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub os: Option<String>,
    pub os_confidence: Option<f32>,
    pub geo_location: Option<String>,
    pub device_type: Option<String>,
    pub device_vendor: Option<String>,
    pub device_model: Option<String>,
    pub device_serial: Option<String>,
    pub device_firmware: Option<String>,
    pub device_version: Option<String>,
    pub device_description: Option<String>,
    pub device_capabilities: Option<String>,
    pub device_features: Option<String>,
    pub device_manufacturer: Option<String>,
    pub device_product: Option<String>,
    pub device_hardware: Option<String>,
    pub device_software: Option<String>,
    pub device_os: Option<String>,
    pub device_os_version: Option<String>,
    pub asn: Option<String>,
    pub asn_org: Option<String>,
    pub asn_country: Option<String>,
    pub asn_description: Option<String>,
    pub asn_prefix: Option<String>,
    pub asn_registry: Option<String>,
    pub provider: Option<String>,
    pub provider_country: Option<String>,
    pub provider_description: Option<String>,
    pub provider_prefix: Option<String>,
    pub interface: Option<String>,
    pub insterface_mac: Option<String>,
    pub interface_description: Option<String>,
    pub interface_speed: Option<u64>,
    pub interface_type: Option<String>,
    pub status: String,
    pub discovered_at: DateTime<Utc>,
    pub rtt_ms: Option<f32>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub vulnerabilities: Vec<serde_json::Value>,
    pub ports: Vec<u16>,
    pub services: Vec<DiscoveredService>,
    pub protocols: Vec<Protocol>,
    pub extra_info: Option<String>,
}

/// A service discovered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredService {
    pub host_ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub extra_info: Option<String>,
    pub discovered_at: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub os_detection: Option<OSDetection>,
    pub vulnerabilities: Vec<serde_json::Value>,
    pub port_state: PortState,
}

/// Error that occurred during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub message: String,
    pub target: Option<String>,
    pub code: Option<i32>,
    pub timestamp: DateTime<Utc>,
    pub severity: ErrorSeverity,
}

/// Error severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
    Unknown,
}

/// Statistics about a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub scan_id: String,
    pub targets_scanned: usize,
    pub hosts_discovered: usize,
    pub services_discovered: usize,
    pub ports_scanned: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub avg_rate: f32,
    pub peak_rate: f32,
    pub total_time_seconds: u64,
    pub network_stats: Option<NetworkStats>,
    pub total_scans: u32,
    pub active_scans: u32,
    pub completed_scans: u32,
    pub failed_scans: u32,
    pub total_hosts_discovered: u32,
    pub total_ports_found: u32,
    pub total_vulnerabilities: u32,
    pub scan_type: Option<ScanType>,
    // pub scan_timing: Option<ScanTiming>, // TODO: Define ScanTiming type
    pub scan_protocols: Vec<Protocol>,
    pub scan_errors: Vec<ScanError>,
    pub scan_start_time: Option<DateTime<Utc>>,
    pub scan_end_time: Option<DateTime<Utc>>,
    pub scan_duration: Option<u64>,
    pub scan_command: Option<String>,
    pub scan_metadata: HashMap<String, serde_json::Value>,
    pub scan_results: Vec<DiscoveredHost>,
    pub scan_service_results: Vec<DiscoveredService>,
    pub scan_summary: Option<String>,
    pub scan_raw_output: Option<String>,
    pub scan_custom_args: Vec<String>,
    pub scan_vulnerabilities: Vec<serde_json::Value>,
    pub scan_open_ports: Vec<DiscoveredService>,
    pub scan_additional_info: HashMap<String, serde_json::Value>,
    pub scan_interface: Option<String>,
    pub scan_rate: Option<u64>,
    pub scan_sink_types: Vec<String>,
    pub scan_source_type: String,
    pub scan_modules: Vec<String>,
    pub scan_extra_args: Vec<String>,
    pub scan_port_ranges: Option<Vec<PortRange>>,
    pub scan_target_ips: Vec<IpAddr>,
    pub scan_target_hostnames: Vec<String>,
    pub scan_target_cidrs: Vec<String>,
    pub scan_target_metadata: HashMap<String, serde_json::Value>,
    pub scan_target_options: HashMap<String, serde_json::Value>,
}

/// Network utilization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_loss_rate: f32,
    pub avg_latency_ms: f32,
    pub max_latency_ms: f32,
    pub min_latency_ms: f32,
    pub jitter_ms: f32,
    // pub protocol_stats: HashMap<Protocol, ProtocolStats>, // TODO: Define ProtocolStats type
    // pub connection_stats: HashMap<String, ConnectionStats>, // TODO: Define ConnectionStats type
}

/// OS detection results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSDetection {
    pub name: String,
    pub family: String,
    pub version: Option<String>,
    pub accuracy: f32,
    pub vendor: Option<String>,
    pub generation: Option<String>,
    pub fingerprint: Option<String>,
    pub cpe: Vec<String>,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Discovery => write!(f, "Discovery"),
            ScanType::Quick => write!(f, "Quick"),
            ScanType::Comprehensive => write!(f, "Comprehensive"),
            ScanType::Stealth => write!(f, "Stealth"),
            ScanType::PortScan => write!(f, "Port Scan"),
            ScanType::ServiceDetection => write!(f, "Service Detection"),
            ScanType::OsDetection => write!(f, "OS Detection"),
            ScanType::VulnerabilityScan => write!(f, "Vulnerability Scan"),
            ScanType::PivotScan => write!(f, "Pivot Scan"),
            ScanType::IoTScan => write!(f, "IoT Scan"),
            ScanType::NetworkScan => write!(f, "Network Scan"),
            ScanType::JumpHostScan => write!(f, "Jump Host Scan"),
            ScanType::CloudScan => write!(f, "Cloud Scan"),
            ScanType::BotnetScan => write!(f, "Botnet Scan"),
            ScanType::SpiderScan => write!(f, "Spider Scan"),
            ScanType::WebAppScan => write!(f, "Web App Scan"),
            ScanType::PenetrationTest => write!(f, "Penetration Test"),
            ScanType::NetworkDiscovery => write!(f, "Network Discovery"),
            ScanType::NetworkMapping => write!(f, "Network Mapping"),
            ScanType::HoneypotScan => write!(f, "Honeypot Scan"),
            ScanType::VulnerabilityAssessment => write!(f, "Vulnerability Assessment"),
            ScanType::Custom { options } => write!(f, "Custom: {}", options),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Sctp => write!(f, "SCTP"),
        }
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Queued => write!(f, "Queued"),
            ScanStatus::Running => write!(f, "Running"),
            ScanStatus::Completed => write!(f, "Completed"),
            ScanStatus::Failed(msg) => write!(f, "Failed: {}", msg),
            ScanStatus::Cancelled => write!(f, "Cancelled"),
            ScanStatus::Paused => write!(f, "Paused"),
        }
    }
}
