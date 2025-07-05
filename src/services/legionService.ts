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
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export interface ScanOptions {
  targetIp: string;
  scanType: string;
}

export interface ScanProgressEvent {
  scanId: string;
  progress: number;
  message?: string;
}

export interface VulnerabilityResult {
  id: string;
  severity: string;
  description: string;
  port?: number;
  service?: string;
}

export interface TauriLegionService {
  startScan(options: ScanOptions): Promise<string>;
  stopScan(scanId: string): Promise<void>;
  getVulnerabilities(severityFilter?: string): Promise<VulnerabilityResult[]>;
  onScanProgress(scanId: string, callback: (progress: ScanProgressEvent) => void): Promise<UnlistenFn>;
  removeScanListener(scanId: string): Promise<void>;
  isScanning(): Promise<boolean>;
}

class TauriLegionServiceImpl implements TauriLegionService {
  private scanListeners: Map<string, UnlistenFn> = new Map();

  async startScan(options: ScanOptions): Promise<string> {
    // Send as single options object
    const scanId = await invoke<string>('start_scan', { options });
    return scanId;
  }

  async stopScan(scanId: string): Promise<void> {
    await invoke('stop_scan', { scanId });
  }

  async getVulnerabilities(severityFilter?: string): Promise<VulnerabilityResult[]> {
    // Handle optional parameter
    const args = severityFilter ? { severityFilter } : {};
    return await invoke<VulnerabilityResult[]>('get_vulnerabilities', args);
  }

  async onScanProgress(scanId: string, callback: (progress: ScanProgressEvent) => void): Promise<UnlistenFn> {
    // Listen to scan-specific progress events
    const eventName = `scan-progress-${scanId}`;
    const unlisten = await listen<ScanProgressEvent>(eventName, (event) => {
      callback(event.payload);
    });
    
    // Store the unlisten function
    this.scanListeners.set(scanId, unlisten);
    
    return unlisten;
  }

  async removeScanListener(scanId: string): Promise<void> {
    const unlisten = this.scanListeners.get(scanId);
    if (unlisten) {
      unlisten();
      this.scanListeners.delete(scanId);
    }
  }

  async isScanning(): Promise<boolean> {
    return await invoke<boolean>('is_scanning');
  }
}

// Export singleton instance
export const legionService: TauriLegionService = new TauriLegionServiceImpl();