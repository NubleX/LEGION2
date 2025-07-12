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

import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { ScanConfig } from '../types/scanning';

interface ScanOptions {
  targetIp: string;
  scanType: string;
  progress: number;
}

interface LegionStore {
  currentScan: ScanOptions | null;
  isScanning: boolean;
  verboseOutput: string[];
  vulnerabilities: any[];
  
  startScan: (config: ScanConfig) => Promise<void>;
  stopScan: () => Promise<void>;
  updateScanProgress: (scanId: string, progress: number) => void;
  loadVulnerabilities: (severityFilter?: string) => Promise<void>;
  appendVerboseOutput: (message: string) => void;
  clearVerboseOutput: () => void;
}

const useLegionStore = create<LegionStore>((set, get) => ({
  currentScan: null,
  isScanning: false,
  verboseOutput: [],
  vulnerabilities: [],

  startScan: async (config: ScanConfig) => {
    try {
      console.log('Legion Store: Starting scan with config:', config);
      
      // Extract the first target IP from the targets string (comma or newline separated)
      const targetsList = config.targets.split(/[,\n]/).map(t => t.trim()).filter(t => t.length > 0);
      if (targetsList.length === 0) {
        throw new Error('No valid targets specified');
      }
      
      // Map frontend ScanConfig to backend ScanOptions
      // Convert scan type to match backend enum format
      const scanTypeMap: Record<string, string> = {
        'quick': 'Quick',
        'comprehensive': 'Comprehensive', 
        'stealth': 'Stealth',
        'discovery': 'Discovery',
        'port-scan': 'PortScan',
        'service-scan': 'ServiceDetection',
        'vulnerability': 'Vulnerability'
      };
      
      const scanOptions = {
        target_ip: targetsList[0], // Backend currently supports single target
        scan_type: scanTypeMap[config.scanType] || config.scanType,
        port_range: config.ports || config.portRange || null,
        max_concurrent: config.maxConcurrent || null,
        timeout: config.timeout || null,
        stealth_mode: config.stealthMode || null,
        os_detection: config.osDetection || config.detectOS || null,
        service_detection: config.serviceDetection || config.detectVersions || null,
        vulnerability_scan: config.vulnerabilityAssessment || null
      };

      console.log('Legion Store: Calling Tauri backend with:', { options: scanOptions });
      
      await invoke('start_network_scan', { 
        options: scanOptions
      });
      
      console.log('Legion Store: Backend call successful!');
      
      set({ 
        isScanning: true, 
        currentScan: { 
          targetIp: scanOptions.target_ip,
          scanType: scanOptions.scan_type,
          progress: 0 
        } 
      });
      
      // Start listening for progress updates
      await listen('scan-event', (event: any) => {
        const scanEvent = event.payload;
        if (scanEvent.event_type === 'ScanProgress') {
          get().updateScanProgress(scanEvent.scan_id, scanEvent.data.progress);
        }
      });
      
    } catch (error) {
      console.error('Failed to start scan:', error);
      set({ isScanning: false, currentScan: null });
    }
  },

  stopScan: async () => {
    try {
      const { currentScan } = get();
      if (currentScan) {
        await invoke('cancel_network_scan', { scanId: 'current' });
      }
      set({ isScanning: false, currentScan: null });
    } catch (error) {
      console.error('Failed to stop scan:', error);
    }
  },

  updateScanProgress: (_scanId: string, progress: number) => {
    set(state => ({
      currentScan: state.currentScan ? {
        ...state.currentScan,
        progress
      } : null
    }));
  },

  loadVulnerabilities: async (severityFilter?: string) => {
    try {
      // Implementation would call backend API
      console.log('Loading vulnerabilities with filter:', severityFilter);
    } catch (error) {
      console.error('Failed to load vulnerabilities:', error);
    }
  },

  appendVerboseOutput: (message: string) => {
    set(state => ({
      verboseOutput: [...state.verboseOutput, message]
    }));
  },

  clearVerboseOutput: () => {
    set({ verboseOutput: [] });
  }
}));

export { useLegionStore };
export type { LegionStore };