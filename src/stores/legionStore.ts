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
  scanId?: string;
  targetIp: string;
  scanType: string;
  progress: number;
}

interface LegionStore {
  currentScan: ScanOptions | null;
  isScanning: boolean;
  verboseOutput: string[];
  vulnerabilities: any[];
  activeScans: Map<string, any>;
  currentProgress: Map<string, any>;
  scanHistory: any[];
  statistics: any;
  
  startScan: (config: ScanConfig) => Promise<void>;
  stopScan: () => Promise<void>;
  cancelScan: (scanId: string) => Promise<void>;
  cancelAllScans: () => Promise<void>;
  updateScanProgress: (scanId: string, progress: number) => void;
  loadVulnerabilities: (severityFilter?: string) => Promise<void>;
  appendVerboseOutput: (message: string) => void;
  clearVerboseOutput: () => void;
  refreshStatistics: () => Promise<void>;
}

const useLegionStore = create<LegionStore>((set, get) => {
  // Set up scan event listener once when store is created
  const setupEventListener = async () => {
    try {
      await listen('scan-event', (event: any) => {
        const scanEvent = event.payload;
        
        switch (scanEvent.event_type) {
          case 'ScanProgress':
            if (scanEvent.data && scanEvent.data.progress !== undefined) {
              get().updateScanProgress(scanEvent.scan_id, scanEvent.data.progress);
            }
            break;
          case 'ScanOutput':
            // ScanOutput is now handled directly by the Live Output panel
            // Remove this to avoid duplication
            break;
          case 'ScanCompleted':
            set(state => {
              const newActiveScans = new Map(state.activeScans);
              newActiveScans.delete(scanEvent.scan_id);
              
              return {
                activeScans: newActiveScans,
                isScanning: newActiveScans.size > 0,
                currentScan: newActiveScans.size > 0 ? state.currentScan : null,
                statistics: {
                  ...state.statistics,
                  active_scans: newActiveScans.size,
                  completed_scans: state.statistics.completed_scans + 1
                }
              };
            });
            break;
          case 'ScanError':
            set(state => {
              const newActiveScans = new Map(state.activeScans);
              newActiveScans.delete(scanEvent.scan_id);
              
              return {
                activeScans: newActiveScans,
                isScanning: newActiveScans.size > 0,
                currentScan: newActiveScans.size > 0 ? state.currentScan : null,
                statistics: {
                  ...state.statistics,
                  active_scans: newActiveScans.size,
                  failed_scans: state.statistics.failed_scans + 1
                }
              };
            });
            break;
        }
      });
    } catch (error) {
      console.error('Failed to set up scan event listener:', error);
    }
  };
  
  // Initialize the event listener
  setupEventListener();

  return {
    currentScan: null,
    isScanning: false,
    verboseOutput: [],
    vulnerabilities: [],
    activeScans: new Map(),
    currentProgress: new Map(),
    scanHistory: [],
    statistics: {
      total_scans: 0,
      active_scans: 0,
      completed_scans: 0,
      failed_scans: 0,
      total_hosts_discovered: 0,
      total_ports_discovered: 0,
      total_vulnerabilities: 0,
      scan_time_total: 0,
      avg_scan_duration: 0
    },

  startScan: async (config: ScanConfig) => {
    console.log('legionStore.startScan called with config:', config);
    try {
      // Extract the first target IP from the targets string (comma or newline separated)
      const targetsList = config.targets.split(/[,\n]/).map(t => t.trim()).filter(t => t.length > 0);
      console.log('Parsed targets:', targetsList);
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

      console.log('Calling invoke with scanOptions:', scanOptions);
      const scanId = await invoke('start_network_scan', { 
        options: scanOptions
      }) as string;
      console.log('Received scanId from backend:', scanId);
      
      set(state => { 
        const newActiveScans = new Map(state.activeScans);
        newActiveScans.set(scanId, {
          id: scanId,
          target_id: scanOptions.target_ip,
          scan_type: scanOptions.scan_type,
          status: 'running',
          start_time: new Date().toISOString(),
          open_ports: [],
          vulnerabilities: [],
          progress: 0
        });
        
        return {
          isScanning: true, 
          currentScan: { 
            scanId: scanId,
            targetIp: scanOptions.target_ip,
            scanType: scanOptions.scan_type,
            progress: 0 
          },
          activeScans: newActiveScans,
          verboseOutput: [`Starting nmap scan for ${scanOptions.target_ip}...`], // Add initial message
          statistics: {
            ...state.statistics,
            active_scans: newActiveScans.size
          }
        };
      });
      
      // Set a timeout as fallback in case scan completion event is missed
      setTimeout(() => {
        const state = get();
        if (state.activeScans.has(scanId)) {
          
          set(state => {
            const newActiveScans = new Map(state.activeScans);
            newActiveScans.delete(scanId);
            
            return {
              activeScans: newActiveScans,
              isScanning: newActiveScans.size > 0,
              currentScan: newActiveScans.size > 0 ? state.currentScan : null,
              statistics: {
                ...state.statistics,
                active_scans: newActiveScans.size,
                completed_scans: state.statistics.completed_scans + 1
              }
            };
          });
        }
      }, 5 * 60 * 1000); // 5 minutes timeout
      
    } catch (error) {
      console.error('Failed to start scan:', error);
      set({ isScanning: false, currentScan: null });
    }
  },

  stopScan: async () => {
    try {
      const { currentScan } = get();
      if (currentScan && currentScan.scanId) {
        await invoke('cancel_network_scan', { scan_id: currentScan.scanId });
      }
      set({ isScanning: false, currentScan: null });
    } catch (error) {
      console.error('Failed to stop scan:', error);
      // Still set scanning to false even if cancel fails
      set({ isScanning: false, currentScan: null });
    }
  },

  updateScanProgress: (scanId: string, progress: number) => {
    set(state => {
      const newProgress = new Map(state.currentProgress);
      newProgress.set(scanId, { progress, scanId });
      
      const newActiveScans = new Map(state.activeScans);
      if (newActiveScans.has(scanId)) {
        const scan = newActiveScans.get(scanId);
        newActiveScans.set(scanId, { ...scan, progress });
      }
      
      return {
        currentProgress: newProgress,
        activeScans: newActiveScans,
        currentScan: state.currentScan && state.currentScan.scanId === scanId ? {
          ...state.currentScan,
          progress
        } : state.currentScan
      };
    });
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
  },

  cancelScan: async (scanId: string) => {
    try {
      await invoke('cancel_network_scan', { scan_id: scanId });
      
      set(state => {
        const newActiveScans = new Map(state.activeScans);
        newActiveScans.delete(scanId);
        
        return {
          activeScans: newActiveScans,
          isScanning: newActiveScans.size > 0,
          currentScan: newActiveScans.size > 0 ? state.currentScan : null,
          statistics: {
            ...state.statistics,
            active_scans: newActiveScans.size
          }
        };
      });
    } catch (error) {
      console.error('Failed to cancel scan:', error);
    }
  },

  cancelAllScans: async () => {
    const { activeScans } = get();
    for (const scanId of activeScans.keys()) {
      try {
        await invoke('cancel_network_scan', { scan_id: scanId });
      } catch (error) {
        console.error('Failed to cancel scan:', scanId, error);
      }
    }
    
    set({
      activeScans: new Map(),
      isScanning: false,
      currentScan: null
    });
  },

  refreshStatistics: async () => {
    try {
      const stats = await invoke('get_scan_statistics');
      set({ statistics: stats });
    } catch (error) {
      console.error('Failed to refresh statistics:', error);
    }
  }
  };
});

export { useLegionStore };
export type { LegionStore };