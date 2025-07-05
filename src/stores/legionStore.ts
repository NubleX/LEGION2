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

import { create } from 'zustand';
import { legionService, type ScanProgressEvent, type VulnerabilityResult } from '../services/legionService.ts';
import type { UnlistenFn } from '@tauri-apps/api/event';

interface ScanInfo {
  id: string;
  targetIp: string;
  scanType: string;
  progress: number;
  isActive: boolean;
  unlisten?: UnlistenFn;
}

interface LegionStore {
  // State
  currentScan: ScanInfo | null;
  vulnerabilities: VulnerabilityResult[];
  isScanning: boolean;
  verboseOutput: string[];
  
  // Actions
  startScan: (targetIp: string, scanType: string) => Promise<void>;
  stopScan: () => Promise<void>;
  updateScanProgress: (scanId: string, progress: number) => void;
  loadVulnerabilities: (severityFilter?: string) => Promise<void>;
  appendVerboseOutput: (message: string) => void;
  clearVerboseOutput: () => void;
}

export const useLegionStore = create<LegionStore>((set, get) => ({
  // Initial state
  currentScan: null,
  vulnerabilities: [],
  isScanning: false,
  verboseOutput: [],

  // Start scan
  startScan: async (targetIp: string, scanType: string) => {
    try {
      // Stop any existing scan
      const currentScan = get().currentScan;
      if (currentScan?.isActive) {
        await get().stopScan();
      }

      // Start new scan with combined options
      const scanId = await legionService.startScan({ targetIp, scanType });
      
      // Set up progress listener
      const unlisten = await legionService.onScanProgress(scanId, (progress: ScanProgressEvent) => {
        get().updateScanProgress(scanId, progress.progress);
        if (progress.message) {
          get().appendVerboseOutput(progress.message);
        }
      });

      // Update state
      set({
        currentScan: {
          id: scanId,
          targetIp,
          scanType,
          progress: 0,
          isActive: true,
          unlisten
        },
        isScanning: true
      });

    } catch (error) {
      console.error('Failed to start scan:', error);
      get().appendVerboseOutput(`Error: ${error}`);
      throw error;
    }
  },

  // Stop scan
  stopScan: async () => {
    const currentScan = get().currentScan;
    if (!currentScan) return;

    try {
      // Stop the scan
      await legionService.stopScan(currentScan.id);
      
      // Remove listener
      await legionService.removeScanListener(currentScan.id);
      
      // Clean up unlisten function if exists
      if (currentScan.unlisten) {
        currentScan.unlisten();
      }

      // Update state
      set({
        currentScan: null,
        isScanning: false
      });
      
      get().appendVerboseOutput('Scan stopped by user');
    } catch (error) {
      console.error('Failed to stop scan:', error);
      get().appendVerboseOutput(`Error stopping scan: ${error}`);
    }
  },

  // Update scan progress
  updateScanProgress: (scanId: string, progress: number) => {
    set((state) => {
      if (state.currentScan?.id === scanId) {
        return {
          currentScan: {
            ...state.currentScan,
            progress
          }
        };
      }
      return state;
    });

    // Check if scan completed
    if (progress >= 100) {
      const currentScan = get().currentScan;
      if (currentScan?.id === scanId) {
        // Clean up listener
        legionService.removeScanListener(scanId);
        
        set({
          currentScan: {
            ...currentScan,
            isActive: false
          },
          isScanning: false
        });
        
        get().appendVerboseOutput('Scan completed successfully');
        // Reload vulnerabilities after scan completes
        get().loadVulnerabilities();
      }
    }
  },

  // Load vulnerabilities
  loadVulnerabilities: async (severityFilter?: string) => {
    try {
      const vulnerabilities = await legionService.getVulnerabilities(severityFilter);
      set({ vulnerabilities });
    } catch (error) {
      console.error('Failed to load vulnerabilities:', error);
      get().appendVerboseOutput(`Error loading vulnerabilities: ${error}`);
    }
  },

  // Verbose output management
  appendVerboseOutput: (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    const formattedMessage = `[${timestamp}] ${message}`;
    
    set((state) => ({
      verboseOutput: [...state.verboseOutput, formattedMessage].slice(-1000) // Keep last 1000 lines
    }));
  },

  clearVerboseOutput: () => {
    set({ verboseOutput: [] });
  }
}));