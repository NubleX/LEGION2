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
      const targets = config.targets;
      const ports = config.ports && config.ports.trim() !== '' ? config.ports : '1-65535';

      // Build plans based on selected tools
      const plans: any[] = [];

      if (config.useMasscan) {
        plans.push({
          scan_id: crypto.randomUUID(),
          targets,
          ports,
          rate: config.rate || 1000,
          extra: [],
          modules: [],
          source_type: 'masscan',
          sink_types: ['ui', 'db'],
        });
      }

      if (config.useNmap) {
        const nmapArgs: string[] = [];

        // Preset options based on scan type
        switch (config.scanType) {
          case 'quick':
            nmapArgs.push('-T4', '-F');
            break;
          case 'comprehensive':
            nmapArgs.push('-sS', '-sV', '-O', '-A', '-T4');
            break;
          case 'stealth':
            nmapArgs.push('-sS', '-T2', '-f', '--randomize-hosts');
            break;
        }

        if (config.detectOS) nmapArgs.push('-O');
        if (config.detectVersions) nmapArgs.push('-sV');
        if (config.skipPing) nmapArgs.push('-Pn');
        if (config.extra) {
          nmapArgs.push(...config.extra.split(' '));
        }

        plans.push({
          scan_id: crypto.randomUUID(),
          targets,
          ports,
          rate: null,
          extra: nmapArgs,
          modules: [],
          source_type: 'nmap',
          sink_types: ['ui', 'db'],
        });
      }

      set(() => ({
        scanInProgress: true,
        liveOutput: [`Starting scan for ${targets} using ${plans.map(p => p.source_type).join(' & ')}...`],
      }));

      for (const plan of plans) {
        await invoke('engine_execute', { plan });
      }
    },

    clearOutput: () => {
      set({ liveOutput: [] });
    }
  };
});

export default useAppStore;