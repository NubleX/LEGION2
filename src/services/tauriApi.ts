// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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

import { invoke } from '@tauri-apps/api/core';
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

  // Core scanning methods
  async startScan(target: ScanTarget): Promise<string> {
    return await invoke('start_scan', { target });
  }

  async cancelScan(scanId: string): Promise<void> {
    return await invoke('cancel_scan', { scanId });
  }

  async getScanResults(scanId?: string): Promise<ScanResult[]> {
    return await invoke('get_scan_results', { scanId });
  }

  async getActiveScans(): Promise<ScanResult[]> {
    return await invoke('get_active_scans');
  }

  async scanNetworkRange(request: NetworkRangeRequest): Promise<string[]> {
    return await invoke('scan_network_range', { range: request });
  }

  async getScanStatistics(): Promise<ScanStatistics> {
    return await invoke('get_scan_statistics');
  }

  async getHosts(): Promise<Host[]> {
    return await invoke('get_hosts');
  }

  async getHostDetails(hostId: string): Promise<HostDetails> {
    return await invoke('get_host_details', { hostId });
  }

  async getVulnerabilities(): Promise<Vulnerability[]> {
    return await invoke('get_vulnerabilities');
  }

  async createProject(name: string, description?: string): Promise<Project> {
    return await invoke('create_project', { name, description });
  }

  async listProjects(): Promise<Project[]> {
    return await invoke('list_projects');
  }

  // Progress listener management
  addProgressListener(id: string, listener: (progress: ScanProgress) => void) {
    this.progressListeners.set(id, listener);
  }

  removeProgressListener(id: string) {
    this.progressListeners.delete(id);
  }
}

export const legionService = new TauriLegionService();