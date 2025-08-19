export interface Host {
    id: string;
    ip: string;
    hostname?: string;
    mac_address?: string;
    vendor?: string;
    nic_vendor?: string;
    nic_model?: string;
    os_name?: string;
    os_family?: string;
    os_accuracy?: number;
    status: string;
    last_seen: string;
    created_at: string;
    updated_at: string;
    port_count: number;
    vulnerability_count: number;
    notes?: string;
    tags: string[];
    scan_progress?: number;
}

export enum Protocol {
    Tcp = "tcp",
    Udp = "udp",
    Icmp = "icmp",
    Sctp = "sctp",
}

export enum PortState {
    Open = "open",
    Closed = "closed",
    Filtered = "filtered",
    Unknown = "unknown",
}

export enum Severity {
    Info = "info",
    Low = "low",
    Medium = "medium",
    High = "high",
    Critical = "critical",
}

export enum ScanType {
    Discovery = "discovery",
    Quick = "quick",
    Comprehensive = "comprehensive",
    Stealth = "stealth",
    PortScan = "port_scan",
    ServiceDetection = "service_detection",
    OsDetection = "os_detection",
    Vulnerability = "vulnerability",
    Custom = "custom",
}

export interface PortRange {
    start: number;
    end: number;
    top_ports?: number;
}

export interface ScanTarget {
    id: string;
    ip: string;
    scan_type: ScanType;
    ports?: number[];
    port_ranges?: PortRange[];
    protocols: Protocol[];
    options: Record<string, any>;
}

export enum ScanStatus {
    Queued = "queued",
    Running = "running",
    Completed = "completed",
    Failed = "failed",
    Cancelled = "cancelled",
    Paused = "paused",
}

export interface NetworkStats {
    packets_sent: number;
    packets_received: number;
    bytes_sent: number;
    bytes_received: number;
    packet_loss_rate: number;
}

export interface ScanProgress {
    scan_id: string;
    status: ScanStatus;
    percentage: number;
    stage: string;
    targets_completed: number;
    targets_total: number;
    hosts_found: number;
    services_found: number;
    eta_seconds?: number;
    started_at: string;
    updated_at: string;
    rate?: number;
    details: Record<string, any>;
    progress: number;
    current_target?: string;
    hosts_discovered: number;
    ports_found: number;
    vulnerabilities: number;
    elapsed_time: number;
}

export interface ScanStatistics {
    scan_id: string;
    targets_scanned: number;
    hosts_discovered: number;
    services_discovered: number;
    ports_scanned: number;
    open_ports: number;
    closed_ports: number;
    filtered_ports: number;
    avg_rate: number;
    peak_rate: number;
    total_time_seconds: number;
    network_stats?: NetworkStats;
    total_scans: number;
    active_scans: number;
    completed_scans: number;
    failed_scans: number;
    total_hosts_discovered: number;
    total_ports_found: number;
    total_vulnerabilities: number;
}

export interface OSDetection {
    name: string;
    family: string;
    version?: string;
    accuracy: number;
    vendor?: string;
    generation?: string;
    fingerprint?: string;
    cpe: string[];
}

export enum ScanTiming {
    Paranoid = "paranoid",
    Sneaky = "sneaky",
    Polite = "polite",
    Normal = "normal",
    Aggressive = "aggressive",
    Insane = "insane",
}

export interface ScriptResult {
    id: string;
    output: string;
    elements?: Record<string, string>;
}

