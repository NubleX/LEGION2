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

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

export async function startScan(targets: string, ports: string, rate = 5000) {
  const plan = {
    scan_id: crypto.randomUUID(),
    targets, ports, rate,
    extra: [],
    modules: [] // add transforms later
  };
  await invoke("engine_execute", { plan });
}

export async function subscribeObs(onHost: (o:any)=>void, onService:(o:any)=>void, onLog:(o:any)=>void) {
  const unsubs: Array<() => void> = [];
  unsubs.push(await listen("obs:service", e => onService(e.payload)));
  unsubs.push(await listen("obs:host", e => onHost(e.payload)));
  unsubs.push(await listen("obs:metric", e => onLog(e.payload)));
  return () => unsubs.forEach(u => u());
}

export interface ScanTarget {
  id: string;
  ip: string;
  hostname?: string;
  ports: number[];
  scan_type: 'quick' | 'comprehensive' | 'stealth';
  options?: any;
}

export interface ScanOptions {
  target_ip: string;
  scan_type: 'quick' | 'comprehensive' | 'stealth' | 'discovery' | 'port_scan' | 'service_detection' | 'vulnerability';
  port_range?: string;
  max_concurrent?: number;
  timeout?: number;
  stealth_mode?: boolean;
  os_detection?: boolean;
  service_detection?: boolean;
  vulnerability_scan?: boolean;
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
  completed_scans: number;
  failed_scans: number;
  total_hosts_discovered: number;
  total_ports_found: number;
  total_vulnerabilities: number;
  hosts_discovered: number;
  vulnerabilities_found: number;
  last_scan_time?: string;
}

export interface HostDetails {
  host: Host;
  ports: Port[];
  vulnerabilities: Vulnerability[];
}

export enum ScanEventType {
  ScanStarted = 'scan_started',
  ScanProgress = 'scan_progress',
  ScanCompleted = 'scan_completed',
  ScanFailed = 'scan_failed',
  ScanCancelled = 'scan_cancelled',
  HostDiscovered = 'host_discovered',
  PortFound = 'port_found',
  VulnerabilityFound = 'vulnerability_found',
  OSDetected = 'os_detected'
}

export interface ScanEvent {
  scan_id: string;
  event_type: ScanEventType;
  timestamp: string;
  data: any;
}

// Fixed API functions with proper error handling
// Global state to ensure only one event stream is ever created
let globalEventStreamSetup = false;
let globalEventStreamPromise: Promise<void> | null = null;

// Global event listener management
let globalEventListeners: ((event: any) => void)[] = [];
let globalUnlisten: (() => void) | null = null;

export const scanAPI = {
  // Start a network scan
  async startNetworkScan(options: ScanOptions): Promise<string> {
    try {
      const scanId = await invoke<string>('start_network_scan', { options });
      return scanId;
    } catch (error) {
      console.error('Failed to start network scan:', error);
      throw new Error(`Scan start failed: ${error}`);
    }
  },

  // Cancel a running scan
  async cancelNetworkScan(scanId: string): Promise<void> {
    try {
      await invoke('cancel_network_scan', { scanId });
    } catch (error) {
      console.error('Failed to cancel scan:', error);
      throw new Error(`Scan cancellation failed: ${error}`);
    }
  },

  // Get current scan progress
  async getScanProgress(): Promise<ScanProgress[]> {
    try {
      const progress = await invoke<ScanProgress[]>('get_scan_progress');
      return progress;
    } catch (error) {
      console.error('Failed to get scan progress:', error);
      return []; // Return empty array on error instead of throwing
    }
  },

  // Check if any scans are running
  async isScanning(): Promise<boolean> {
    try {
      const scanning = await invoke<boolean>('is_scanning');
      return scanning;
    } catch (error) {
      console.error('Failed to check scanning status:', error);
      return false; // Return false on error
    }
  },

  // Get scan statistics
  async getScanStatistics(): Promise<ScanStatistics> {
    try {
      const stats = await invoke<ScanStatistics>('get_scan_statistics');
      return stats;
    } catch (error) {
      console.error('Failed to get scan statistics:', error);
      // Return default statistics on error
      return {
        total_scans: 0,
        active_scans: 0,
        hosts_discovered: 0,
        vulnerabilities_found: 0,
        completed_scans: 0,
        failed_scans: 0,
        total_hosts_discovered: 0,
        total_ports_found: 0,
        total_vulnerabilities: 0
      };
    }
  },

  // Scan a network range
  async scanNetworkRange(request: NetworkRangeRequest): Promise<string[]> {
    try {
      const scanIds = await invoke<string[]>('scan_network_range', {
        cidr: request.cidr,
        exclude: request.exclude,
        scanType: request.scan_type
      });
      return scanIds;
    } catch (error) {
      console.error('Failed to start network range scan:', error);
      throw new Error(`Network range scan failed: ${error}`);
    }
  },

  // Setup event stream from backend (singleton with promise caching)
  async setupEventStream(): Promise<void> {
    if (globalEventStreamSetup) {
      console.log('Event stream already setup, skipping');
      return;
    }
    
    if (globalEventStreamPromise) {
      console.log('Event stream setup in progress, waiting...');
      return globalEventStreamPromise;
    }
    
    globalEventStreamPromise = (async () => {
      try {
        await invoke('setup_event_stream');
        globalEventStreamSetup = true;
        console.log('Event stream setup completed');
      } catch (error) {
        console.error('Failed to setup event stream:', error);
        globalEventStreamPromise = null; // Reset on error
        throw error;
      }
    })();
    
    return globalEventStreamPromise;
  },

  // Listen to scan events with proper deduplication
  async listenToScanEvents(callback: (event: any) => void): Promise<() => void> {
    console.log('listenToScanEvents called, current listeners:', globalEventListeners.length);
    
    try {
      // Setup the event stream first (only if not already done)
      await this.setupEventStream();
      
      // Add this callback to the list
      globalEventListeners.push(callback);
      console.log('Added callback, total listeners:', globalEventListeners.length);
      
      // Set up the global listener only once
      if (!globalUnlisten) {
        console.log('Setting up single global event listener');
        globalUnlisten = await listen('scan-event', (event) => {
          console.log('Global listener received event, broadcasting to', globalEventListeners.length, 'callbacks');
          globalEventListeners.forEach((listener, index) => {
            try {
              console.log(`Calling callback ${index + 1}/${globalEventListeners.length}`);
              listener(event.payload);
            } catch (error) {
              console.error('Error in event callback:', error);
            }
          });
        });
      } else {
        console.log('Using existing global event listener');
      }
      
      // Return unsubscribe function
      return () => {
        const index = globalEventListeners.indexOf(callback);
        if (index > -1) {
          globalEventListeners.splice(index, 1);
          console.log('Removed listener, remaining:', globalEventListeners.length);
        }
        
        // If no more listeners, clean up the global listener
        if (globalEventListeners.length === 0 && globalUnlisten) {
          console.log('No more listeners, cleaning up global listener');
          globalUnlisten();
          globalUnlisten = null;
        }
      };
    } catch (error) {
      console.error('Failed to listen to scan events:', error);
      return () => {}; // Return no-op function on error
    }
  }
};

// Host API functions
export const hostAPI = {
  // Get all hosts
  async getHosts(statusFilter?: string): Promise<Host[]> {
    try {
      const hosts = await invoke<Host[]>('get_hosts', { statusFilter });
      return hosts;
    } catch (error) {
      console.error('Failed to get hosts:', error);
      return [];
    }
  },

  // Get host by ID
  async getHostById(hostId: string): Promise<Host> {
    try {
      const host = await invoke<Host>('get_host_by_id', { hostId });
      return host;
    } catch (error) {
      console.error('Failed to get host:', error);
      throw new Error(`Failed to get host: ${error}`);
    }
  },

  // Update host OS detection
  async updateHostOSDetection(hostId: string, osDetection: OSDetection): Promise<void> {
    try {
      await invoke('update_host_os_detection', { hostId, osDetection });
    } catch (error) {
      console.error('Failed to update host OS detection:', error);
      throw new Error(`Failed to update OS detection: ${error}`);
    }
  },

  // Get host with OS info
  async getHostWithOSInfo(hostId: string): Promise<Host> {
    try {
      const host = await invoke<Host>('get_host_with_os_info', { hostId });
      return host;
    } catch (error) {
      console.error('Failed to get host with OS info:', error);
      throw new Error(`Failed to get host with OS info: ${error}`);
    }
  }
};

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