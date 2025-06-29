import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';

export interface ScanTarget {
  id: string;
  ip: string;
  hostname?: string;
  ports: number[];
  scan_type: 'quick' | 'comprehensive' | 'stealth';
  options?: any;
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
}

export interface OSDetection {
  os_name: string;
  accuracy?: number;
  vendor?: string;
  family?: string;
  version?: string;
  method?: string;
}

export interface ScanResult {
  id: string;
  target_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  start_time: string;
  end_time?: string;
  duration?: number;
  open_ports: Port[];
  os_detection?: OSDetection;
  vulnerabilities: Vulnerability[];
  scan_type: string;
  error_message?: string;
  raw_output?: string;
}

export interface Port {
  number: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
  banner?: string;
}

export interface Host {
  id: string;
  ip: string;
  hostname?: string;
  os?: string;
  status: string;
  discovered_at: string;
}

export interface Vulnerability {
  id: string;
  name: string;
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  cvss_score?: number;
  references: string[];
}

export interface Project {
  id: string;
  name: string;
  description?: string;
  created_at: string;
}

export interface NetworkRangeRequest {
  cidr: string;
  exclude: string[];
  scan_type: string;
}

export interface ScanStatistics {
  total_scans: number;
  active_scans: number;
  hosts_discovered: number;
  vulnerabilities_found: number;
  last_scan_time?: string;
}

export interface HostDetails {
  host: Host;
  ports: Port[];
  vulnerabilities: Vulnerability[];
}

export class TauriLegionService {
  private progressListeners: Map<string, (progress: ScanProgress) => void> = new Map();

  constructor() {
    this.setupEventListeners();
  }

  private async setupEventListeners() {
    // Listen for scan progress events from your backend
    await listen('scan-progress', (event: any) => {
      const progressEvent = event.payload as { target: string; progress: ScanProgress };
      console.log('Scan progress:', progressEvent);
      
      // Call all progress listeners
      this.progressListeners.forEach((listener) => {
        listener(progressEvent.progress);
      });
    });

    // Listen for scan result events
    await listen('scan-result', (event: any) => {
      console.log('Scan result:', event.payload);
    });

    // Listen for network scan progress
    await listen('network-scan-progress', (event: any) => {
      console.log('Network scan progress:', event.payload);
    });
  }

  // Core scanning commands matching your backend commands.rs
  async startScan(targetIp: string, scanType: string): Promise<string> {
    try {
      return await invoke<string>('start_scan', {
        targetIp,
        scanType: scanType.toLowerCase(), // Convert to match backend expectation
      });
    } catch (error) {
      throw new Error(`Failed to start scan: ${error}`);
    }
  }

  async cancelScan(scanId: string): Promise<void> {
    try {
      await invoke<void>('cancel_scan', { scanId });
    } catch (error) {
      throw new Error(`Failed to cancel scan: ${error}`);
    }
  }

  async getScanResults(): Promise<ScanResult[]> {
    try {
      return await invoke<ScanResult[]>('get_scan_results');
    } catch (error) {
      throw new Error(`Failed to get scan results: ${error}`);
    }
  }

  async getActiveScans(): Promise<Array<{ id: string; status: any }>> {
    try {
      return await invoke<Array<{ id: string; status: any }>>('get_active_scans');
    } catch (error) {
      throw new Error(`Failed to get active scans: ${error}`);
    }
  }

  async scanNetworkRange(cidr: string, exclude: string[], scanType: string): Promise<string[]> {
    try {
      const range = { cidr, exclude, scan_type: scanType.toLowerCase() };
      return await invoke<string[]>('scan_network_range', { range });
    } catch (error) {
      throw new Error(`Failed to scan network range: ${error}`);
    }
  }

  async getScanStatistics(): Promise<ScanStatistics> {
    try {
      return await invoke<ScanStatistics>('get_scan_statistics');
    } catch (error) {
      throw new Error(`Failed to get scan statistics: ${error}`);
    }
  }

  // Database commands matching your backend
  async getHosts(): Promise<Host[]> {
    try {
      return await invoke<Host[]>('get_hosts');
    } catch (error) {
      throw new Error(`Failed to get hosts: ${error}`);
    }
  }

  async getHostDetails(hostId: string): Promise<HostDetails> {
    try {
      return await invoke<HostDetails>('get_host_details', { hostId });
    } catch (error) {
      throw new Error(`Failed to get host details: ${error}`);
    }
  }

  async getVulnerabilities(severityFilter?: string): Promise<Vulnerability[]> {
    try {
      return await invoke<Vulnerability[]>('get_vulnerabilities', { severityFilter });
    } catch (error) {
      throw new Error(`Failed to get vulnerabilities: ${error}`);
    }
  }

  async createProject(name: string, description?: string): Promise<Project> {
    try {
      return await invoke<Project>('create_project', { name, description });
    } catch (error) {
      throw new Error(`Failed to create project: ${error}`);
    }
  }

  async listProjects(): Promise<Project[]> {
    try {
      return await invoke<Project[]>('list_projects');
    } catch (error) {
      throw new Error(`Failed to list projects: ${error}`);
    }
  }

  // Progress listener management
  onScanProgress(scanId: string, callback: (progress: ScanProgress) => void) {
    this.progressListeners.set(scanId, callback);
  }

  removeScanListener(scanId: string) {
    this.progressListeners.delete(scanId);
  }
}

// Singleton instance
export const legionService = new TauriLegionService();