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

// LEGION2 - Minimal event-driven frontend store
// Backend handles all logic via UiSink events and DbSink storage

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { create } from 'zustand';
import type { ScanConfig } from '../types/scanning';

// Simple state reflecting backend events
interface AppState {
  // Current active scans (from engine_execute calls)
  activeScans: Set<string>;

  // Live data from UiSink events
  recentHosts: Array<{ ip: string; hostname?: string; timestamp: string }>;
  recentServices: Array<{ ip: string; port: number; protocol: string; timestamp: string }>;
  liveOutput: string[];

  // Current metrics from backend
  metrics: {
    hosts_discovered: number;
    services_discovered: number;
    processing_rate: number;
    observations_processed: number;
  };

  // Simple UI state
  scanInProgress: boolean;
}

interface AppActions {
  // Simple actions
  startScan: (config: ScanConfig) => Promise<void>;
  cancelScan: (scanId: string) => Promise<void>;
  clearOutput: () => void;
}

const useAppStore = create<AppState & AppActions>((set) => {
  // Set up backend event listeners once
  const setupEventListeners = async () => {
    // Listen to UiSink events
    await listen('obs:host', (event: any) => {
      const hostData = event.payload;
      set(state => ({
        recentHosts: [hostData, ...state.recentHosts.slice(0, 99)] // Keep last 100
      }));
    });

    await listen('obs:service', (event: any) => {
      const serviceData = event.payload;
      set(state => ({
        recentServices: [serviceData, ...state.recentServices.slice(0, 99)] // Keep last 100
      }));
    });

    await listen('obs:progress', (event: any) => {
      const progressData = event.payload;
      set(state => ({
        liveOutput: [...state.liveOutput, progressData.message]
      }));
    });

    await listen('obs:metrics', (event: any) => {
      const metricsData = event.payload;
      set({ metrics: metricsData });
    });

    await listen('obs:error', (event: any) => {
      const errorData = event.payload;
      set(state => ({
        liveOutput: [...state.liveOutput, `ERROR: ${errorData.message}`]
      }));
    });

    await listen('obs:done', () => {
      set({ scanInProgress: false });
    });
  };

  // Initialize listeners
  setupEventListeners().catch(console.error);

  return {
    // Initial state
    activeScans: new Set(),
    recentHosts: [],
    recentServices: [],
    liveOutput: [],
    metrics: {
      hosts_discovered: 0,
      services_discovered: 0,
      processing_rate: 0,
      observations_processed: 0,
    },
    scanInProgress: false,

    // Actions
    startScan: async (config: ScanConfig) => {
      // Convert frontend ScanConfig to backend ScanConfig format
      const backendConfig = {
        targets: config.targets,
        scan_type: config.scanType || 'comprehensive',
        ports: config.ports || undefined,
        use_masscan: config.useMasscan || false,
        masscan_rate: config.masscanRate || undefined,
        nmap_options: config.nmapOptions || undefined,
        modules: [], // Could be populated from frontend later
      };

      set(() => ({
        scanInProgress: true,
        liveOutput: [`Starting ${backendConfig.use_masscan ? 'masscan' : 'nmap'} scan for ${backendConfig.targets}...`]
      }));

      // Use the new command that leverages Plan builders
      const scanId = await invoke('start_scan_with_config', { config: backendConfig }) as string;
      
      set(state => ({
        activeScans: new Set([...state.activeScans, scanId])
      }));
    },

    cancelScan: async (scanId: string) => {
      await invoke('cancel_scan', { scan_id: scanId });
      set(state => {
        const newScans = new Set(state.activeScans);
        newScans.delete(scanId);
        return {
          activeScans: newScans,
          scanInProgress: newScans.size > 0
        };
      });
    },

    clearOutput: () => {
      set({ liveOutput: [] });
    }
  };
});

export default useAppStore;