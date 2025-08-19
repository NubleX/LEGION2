/// Host information as stored in database and shared with frontend

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub nic_vendor: Option<String>,
    pub nic_model: Option<String>,
    pub os_name: Option<String>,
    pub os_family: Option<String>,
    pub os_accuracy: Option<f32>,
    pub status: String,
    pub last_seen: String,
    pub created_at: String,
    pub updated_at: String,
    pub port_count: i32,
    pub vulnerability_count: i32,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub scan_progress: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

impl Protocol {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Sctp => "sctp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Sctp => write!(f, "sctp"),
        }
    }
}

impl FromStr for Protocol {
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

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Tcp
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

// Scan planning and progress models consolidated from scanning and plan modules

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Discovery,
    Quick,
    Comprehensive,
    Stealth,
    PortScan,
    ServiceDetection,
    OsDetection,
    Vulnerability,
    Custom { options: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
    pub top_ports: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: String,
    pub ip: String,
    pub scan_type: ScanType,
    pub ports: Option<Vec<u16>>,
    pub port_ranges: Option<Vec<PortRange>>,
    pub protocols: Vec<Protocol>,
    pub options: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed(String),
    Cancelled,
    Paused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_loss_rate: f32,
}

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
}

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
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTiming {
    Paranoid,
    Sneaky,
    Polite,
    Normal,
    Aggressive,
    Insane,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: &'static str,
    pub category: &'static str,
    pub risk: RiskLevel,
}

impl ServiceInfo {
    pub const fn new(name: &'static str, category: &'static str, risk: RiskLevel) -> Self {
        Self {
            name,
            category,
            risk,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub id: String,
    pub output: String,
    pub elements: Option<HashMap<String, String>>,
}
