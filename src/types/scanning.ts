export type ScanType = 'quick' | 'comprehensive' | 'stealth' | 'custom';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type PortState = 'open' | 'closed' | 'filtered' | 'unfiltered' | 'open|filtered' | 'closed|filtered';
export type Protocol = 'tcp' | 'udp' | 'sctp';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type HostStatus = 'up' | 'down' | 'unknown';

// Network and targeting
export interface IPRange {
  start: string;
  end: string;
  cidr?: string;
}

export interface ScanTarget {
  id: string;
  ip: string;
  hostname?: string;
  ports: number[];
  scan_type: ScanType;
  options?: ScanOptions;
}

export interface ScanOptions {
  timeout?: number;
  timing?: 0 | 1 | 2 | 3 | 4 | 5; // nmap timing templates
  port_range?: string;
  service_detection?: boolean;
  os_detection?: boolean;
  script_scan?: boolean;
  aggressive?: boolean;
  stealth?: boolean;
  fragment_packets?: boolean;
  decoy_scan?: boolean;
  source_port?: number;
  custom_flags?: string;
}

// Scan execution and progress
export interface ScanRequest {
  target: ScanTarget;
  priority?: number;
  max_retries?: number;
}

export interface NetworkScanRequest {
  cidr: string;
  exclude: string[];
  scan_type: string;
  options?: ScanOptions;
}

export interface ScanProgress {
  scan_id: string;
  target_id: string;
  progress: number;
  current_phase: string;
  discovered_hosts: number;
  total_ports_scanned: number;
  open_ports_found: number;
  estimated_time_remaining?: number;
  message?: string;
  start_time: string;
  bytes_sent?: number;
  bytes_received?: number;
}

// Results and discoveries
export interface Port {
  number: number;
  protocol: Protocol;
  state: PortState;
  service?: string;
  version?: string;
  banner?: string;
  confidence?: number;
  cpe?: string[];
  scripts?: ScriptResult[];
}

export interface ScriptResult {
  id: string;
  output: string;
  elements?: Record<string, string>;
}

export interface OSDetection {
  name: string;
  family: string;
  generation?: string;
  vendor?: string;
  accuracy: number;
  fingerprint?: string;
  cpe?: string[];
}

export interface Vulnerability {
  id?: string;
  name: string;
  severity: Severity;
  description: string;
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  references?: string[];
  exploitable?: boolean;
  port_number?: number;
  service?: string;
  discovered_at: string;
}

export interface ScanResult {
  id: string;
  target_id: string;
  status: ScanStatus;
  start_time: string;
  end_time?: string;
  duration?: number;
  open_ports: Port[];
  os_detection?: OSDetection;
  vulnerabilities: Vulnerability[];
  scan_type: string;
  error_message?: string;
  raw_output?: string;
  command_used?: string;
}

// Host management
export interface Host {
  id: string;
  ip: string;
  hostname?: string;
  mac_address?: string;
  vendor?: string;
  os_name?: string;
  os_family?: string;
  os_accuracy?: number;
  status: HostStatus;
  last_seen: string;
  created_at: string;
  updated_at: string;
  port_count: number;
  vulnerability_count: number;
  notes?: string;
  tags?: string[];
}

export interface HostPort {
  id: string;
  host_id: string;
  number: number;
  protocol: Protocol;
  state: PortState;
  service?: string;
  version?: string;
  banner?: string;
  confidence?: number;
  cpe?: string[];
  discovered_at: string;
  last_seen: string;
}

export interface HostVulnerability {
  id: string;
  host_id: string;
  port_id?: string;
  name: string;
  severity: Severity;
  description: string;
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  references?: string[];
  exploitable?: boolean;
  discovered_at: string;
  verified?: boolean;
  false_positive?: boolean;
}

export interface HostDetails {
  host: Host;
  ports: HostPort[];
  vulnerabilities: HostVulnerability[];
  scan_history?: ScanResult[];
}

// Filtering and search
export interface HostFilter {
  status?: HostStatus;
  os_family?: string;
  has_vulnerabilities?: boolean;
  severity_min?: Severity;
  port_range?: { min: number; max: number };
  search_term?: string;
  tags?: string[];
  last_seen_days?: number;
}

export interface VulnerabilityFilter {
  severity?: Severity[];
  exploitable?: boolean;
  verified?: boolean;
  cve_only?: boolean;
  port_numbers?: number[];
  services?: string[];
}

// Statistics and reporting
export interface ScanStatistics {
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  failed_scans: number;
  total_hosts_discovered: number;
  total_ports_discovered: number;
  total_vulnerabilities: number;
  scan_time_total: number;
  avg_scan_duration: number;
}

export interface HostStatistics {
  total_hosts: number;
  up_hosts: number;
  down_hosts: number;
  hosts_with_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  unique_services: number;
  unique_os_families: number;
}

export interface NetworkStatistics {
  network_ranges_scanned: number;
  total_ips_scanned: number;
  responsive_hosts: number;
  average_response_time: number;
  most_common_ports: Array<{ port: number; count: number }>;
  most_common_services: Array<{ service: string; count: number }>;
  os_distribution: Array<{ os_family: string; count: number }>;
}

// Tool integration
export interface ToolResult {
  tool_name: string;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration: number;
  timestamp: string;
}

export interface NmapResult extends ToolResult {
  xml_output?: string;
  hosts_discovered: Host[];
  scan_stats: {
    hosts_up: number;
    hosts_down: number;
    hosts_total: number;
    time_elapsed: number;
  };
}

export interface MasscanResult extends ToolResult {
  hosts_discovered: Array<{
    ip: string;
    ports: Array<{ port: number; protocol: Protocol; state: PortState }>;
  }>;
  scan_rate: number;
  packets_sent: number;
  packets_received: number;
}

// Export and import
export interface ExportOptions {
  format: 'json' | 'csv' | 'xml' | 'html' | 'pdf';
  include_closed_ports?: boolean;
  include_raw_output?: boolean;
  group_by?: 'host' | 'port' | 'service' | 'vulnerability';
  filter?: HostFilter;
}

export interface ImportResult {
  hosts_imported: number;
  ports_imported: number;
  vulnerabilities_imported: number;
  errors: string[];
  warnings: string[];
}

// Events for real-time updates
export interface ScanProgressEvent {
  type: 'scan-progress';
  payload: ScanProgress;
}

export interface ScanCompletedEvent {
  type: 'scan-completed';
  payload: ScanResult;
}

export interface ScanErrorEvent {
  type: 'scan-error';
  payload: {
    scan_id: string;
    error: string;
    timestamp: string;
  };
}

export interface HostDiscoveredEvent {
  type: 'host-discovered';
  payload: Host;
}

export interface VulnerabilityFoundEvent {
  type: 'vulnerability-found';
  payload: {
    host_id: string;
    vulnerability: Vulnerability;
  };
}

export type ScanEvent = 
  | ScanProgressEvent 
  | ScanCompletedEvent 
  | ScanErrorEvent 
  | HostDiscoveredEvent 
  | VulnerabilityFoundEvent;