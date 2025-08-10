use std::net::IpAddr;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// Types of scans that can be performed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    /// Network discovery scan
    Discovery,
    /// Port scanning
    PortScan,
    /// Service detection
    ServiceDetection,
    /// OS detection
    OsDetection,
    /// Vulnerability scanning
    Vulnerability,
    /// Custom scan with specific parameters
    Custom(String),
}

/// Target specification for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// Target specification (IP, CIDR, hostname, etc.)
    pub target: String,
    /// Specific ports to scan (if applicable)
    pub ports: Option<Vec<u16>>,
    /// Port ranges to scan
    pub port_ranges: Option<Vec<PortRange>>,
    /// Protocols to scan
    pub protocols: Vec<Protocol>,
    /// Additional target-specific options
    pub options: HashMap<String, serde_json::Value>,
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
    /// Scan is queued but not started
    Queued,
    /// Scan is currently running
    Running,
    /// Scan completed successfully
    Completed,
    /// Scan failed with error message
    Failed(String),
    /// Scan was cancelled by user
    Cancelled,
    /// Scan was paused
    Paused,
}

/// Progress information for a running scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Unique scan identifier
    pub scan_id: String,
    /// Current status
    pub status: ScanStatus,
    /// Percentage complete (0.0 to 100.0)
    pub percentage: f32,
    /// Current stage/phase of the scan
    pub stage: String,
    /// Number of targets completed
    pub targets_completed: usize,
    /// Total number of targets
    pub targets_total: usize,
    /// Number of hosts discovered
    pub hosts_found: usize,
    /// Number of services discovered
    pub services_found: usize,
    /// Estimated time remaining (seconds)
    pub eta_seconds: Option<u64>,
    /// When the scan started
    pub started_at: DateTime<Utc>,
    /// When the scan was last updated
    pub updated_at: DateTime<Utc>,
    /// Current rate (targets/second, ports/second, etc.)
    pub rate: Option<f32>,
    /// Additional progress details
    pub details: HashMap<String, serde_json::Value>,
    
    // Additional fields expected by nmap scanner  
    /// Progress as decimal (0.0 to 100.0) - alias for percentage
    pub progress: f32,
    /// Current target being scanned
    pub current_target: Option<String>,
    /// Hosts discovered - alias for hosts_found
    pub hosts_discovered: usize,
    /// Ports found/scanned
    pub ports_found: usize,
    /// Vulnerabilities discovered
    pub vulnerabilities: usize,
    /// Elapsed time in seconds
    pub elapsed_time: Option<u64>,
    /// Estimated remaining time
    pub estimated_remaining: Option<u64>,
    /// Progress message
    pub message: Option<String>,
    /// Start time of the scan
    pub start_time: DateTime<Utc>,
    /// Current phase of the scan
    pub current_phase: String,
    /// Target ID being processed
    pub target_id: Option<String>,
    /// Total ports scanned so far
    pub total_ports_scanned: usize,
    /// Total open ports found
    pub open_ports_found: usize,
}

/// Configuration for a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Type of scan to perform
    pub scan_type: ScanType,
    /// Targets to scan
    pub targets: Vec<ScanTarget>,
    /// Timing template (0-5, where 5 is fastest)
    pub timing: Option<u8>,
    /// Maximum number of parallel processes
    pub max_parallel: Option<usize>,
    /// Timeout per target (seconds)
    pub timeout: Option<u64>,
    /// Additional scanner-specific options
    pub scanner_options: HashMap<String, serde_json::Value>,
    /// Whether to perform OS detection
    pub detect_os: bool,
    /// Whether to perform service version detection
    pub detect_versions: bool,
    /// Custom scan arguments/flags
    pub custom_args: Vec<String>,
}

/// Result of a completed scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique scan identifier
    pub scan_id: String,
    /// Scan configuration that was used
    pub config: ScanConfig,
    /// Final scan status
    pub status: ScanStatus,
    /// When the scan started
    pub started_at: DateTime<Utc>,
    /// When the scan completed (or failed/cancelled)
    pub completed_at: Option<DateTime<Utc>>,
    /// Duration in seconds
    pub duration_seconds: Option<u64>,
    /// Hosts discovered during the scan
    pub hosts: Vec<DiscoveredHost>,
    /// Services discovered during the scan
    pub services: Vec<DiscoveredService>,
    /// Any errors encountered during scanning
    pub errors: Vec<ScanError>,
    /// Scanner-specific metadata
    pub metadata: HashMap<String, serde_json::Value>,
    
    // Additional fields expected by nmap scanner
    /// Type of scan performed
    pub scan_type: Option<ScanType>,
    /// Error message (if scan failed)
    pub error_message: Option<String>,
    /// Raw output from scanner
    pub raw_output: Option<String>,
    /// Command that was used
    pub command_used: Option<String>,
    /// Vulnerabilities found
    pub vulnerabilities: Vec<serde_json::Value>,
    /// OS detection results
    pub os_detection: Option<serde_json::Value>,
    /// Open ports found
    pub open_ports: Vec<DiscoveredService>,
}

/// A host discovered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    /// IP address of the host
    pub ip: IpAddr,
    /// Hostname (if resolved)
    pub hostname: Option<String>,
    /// MAC address (if available)
    pub mac_address: Option<String>,
    /// Detected operating system
    pub os: Option<String>,
    /// OS detection confidence (0.0 to 1.0)
    pub os_confidence: Option<f32>,
    /// Host status (up, down, filtered, etc.)
    pub status: String,
    /// When this host was discovered
    pub discovered_at: DateTime<Utc>,
    /// Round-trip time in milliseconds
    pub rtt_ms: Option<f32>,
    /// Additional host metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A service discovered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredService {
    /// Host IP address
    pub host_ip: IpAddr,
    /// Service port number
    pub port: u16,
    /// Protocol (TCP, UDP, etc.)
    pub protocol: Protocol,
    /// Service state (open, closed, filtered, etc.)
    pub state: String,
    /// Detected service name
    pub service: Option<String>,
    /// Service version
    pub version: Option<String>,
    /// Service banner/response
    pub banner: Option<String>,
    /// Additional service information
    pub extra_info: Option<String>,
    /// When this service was discovered
    pub discovered_at: DateTime<Utc>,
    /// Scanner-specific metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Error that occurred during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    /// Error message
    pub message: String,
    /// Target that caused the error (if applicable)
    pub target: Option<String>,
    /// Error code (if applicable)
    pub code: Option<i32>,
    /// When the error occurred
    pub timestamp: DateTime<Utc>,
    /// Error severity
    pub severity: ErrorSeverity,
}

/// Error severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorSeverity {
    /// Informational message
    Info,
    /// Warning that doesn't stop the scan
    Warning,
    /// Error that affects part of the scan
    Error,
    /// Critical error that stops the scan
    Critical,
}

/// Statistics about a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Scan identifier
    pub scan_id: String,
    /// Total targets scanned
    pub targets_scanned: usize,
    /// Total hosts discovered
    pub hosts_discovered: usize,
    /// Total services discovered
    pub services_discovered: usize,
    /// Total ports scanned
    pub ports_scanned: usize,
    /// Open ports found
    pub open_ports: usize,
    /// Closed ports found
    pub closed_ports: usize,
    /// Filtered ports found
    pub filtered_ports: usize,
    /// Average scan rate (targets/second)
    pub avg_rate: f32,
    /// Peak scan rate
    pub peak_rate: f32,
    /// Total scan time in seconds
    pub total_time_seconds: u64,
    /// Network utilization statistics
    pub network_stats: Option<NetworkStats>,
}

/// Network utilization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packet loss rate (0.0 to 1.0)
    pub packet_loss_rate: f32,
}

/// OS detection results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSDetection {
    /// Detected OS name
    pub name: Option<String>,
    /// OS family
    pub family: Option<String>,
    /// OS version
    pub version: Option<String>,
    /// Detection confidence (0.0 to 1.0)
    pub confidence: f32,
    /// CPE (Common Platform Enumeration) strings
    pub cpe: Vec<String>,
    /// Additional OS fingerprinting data
    pub fingerprints: Vec<serde_json::Value>,
}

impl Default for ScanStatus {
    fn default() -> Self {
        ScanStatus::Queued
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Tcp
    }
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Discovery => write!(f, "Discovery"),
            ScanType::PortScan => write!(f, "Port Scan"),
            ScanType::ServiceDetection => write!(f, "Service Detection"),
            ScanType::OsDetection => write!(f, "OS Detection"),
            ScanType::Vulnerability => write!(f, "Vulnerability Scan"),
            ScanType::Custom(name) => write!(f, "Custom: {}", name),
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