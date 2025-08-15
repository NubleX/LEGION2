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
import type { Plan, ScanConfig } from '../types/scanning';

// Simple state reflecting backend events
interface AppState {
  // Live data from UiSink events
  recentHosts: Array<{ ip: string; hostname?: string; timestamp: string }>;
  recentServices: Array<{ ip: string; port: number; protocol: string; timestamp: string }>;
  liveOutput: string[];
  vulnerabilities?: Array<{
    id: string;
    host_ip: string;
    port: number;
    service: string;
    name: string;
    severity: string;
    description: string;
    cvss_score?: number;
    timestamp: string;
  }>;

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

    await listen('obs:vulnerability', (event: any) => {
      const vuln = event.payload;
      const vulnMsg = `🔍 Vulnerability: ${vuln.name} on ${vuln.host_ip}:${vuln.port} (${vuln.severity})`;
      set((state) => ({ 
        liveOutput: [...state.liveOutput, vulnMsg],
        vulnerabilities: [...(state.vulnerabilities || []), vuln]
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
    vulnerabilities: [],
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
      const plans: Plan[] = [];

      if (config.useMasscan) {
        // Use Plan::masscan builder method
        const masscanPlan = await invoke<Plan>('create_masscan_plan', {
          targets,
          ports,
          rate: config.rate || 1000,
        });
        plans.push(masscanPlan);
      }

      if (config.useNmap) {
        // Use appropriate Plan builder based on scan type
        let nmapPlan: Plan;
        const scanId = crypto.randomUUID();

        switch (config.scanType) {
          case 'quick':
            // Use basic nmap plan with quick args
            nmapPlan = await invoke<Plan>('create_nmap_plan', {
              scanId,
              targets,
              ports,
              extraArgs: ['-T4', '-F'],
            });
            break;
          case 'comprehensive':
            // Use Plan::comprehensive builder
            nmapPlan = await invoke<Plan>('create_comprehensive_plan', {
              scanId,
              targets,
              ports,
            });
            break;
          case 'stealth':
            // Use nmap plan with stealth args
            nmapPlan = await invoke<Plan>('create_nmap_plan', {
              scanId,
              targets,
              ports,
              extraArgs: ['-sS', '-T2', '-f', '--randomize-hosts'],
            });
            break;
          default:
            // Standard nmap plan
            const nmapArgs: string[] = [];
            if (config.detectOS) nmapArgs.push('-O');
            if (config.detectVersions) nmapArgs.push('-sV');
            if (config.skipPing) nmapArgs.push('-Pn');
            if (config.extra) {
              nmapArgs.push(...config.extra.split(' '));
            }

            nmapPlan = await invoke<Plan>('create_nmap_plan', {
              scanId,
              targets,
              ports,
              extraArgs: nmapArgs,
            });
        }

        // Add OS detection if requested
        if (config.detectOS && config.scanType !== 'comprehensive') {
          nmapPlan = await invoke<Plan>('plan_with_os_detection', { plan: nmapPlan });
        }

        // Test the module system - add some transform modules
        const availableModules = await invoke<string[]>('get_available_modules');
        console.log('Available transform modules:', availableModules);

        // Add some example modules to the plan
        if (availableModules.length > 0) {
          nmapPlan = await invoke<Plan>('create_plan_with_modules', {
            scanId: nmapPlan.scan_id,
            targets: nmapPlan.targets,
            ports: nmapPlan.ports,
            sourceType: nmapPlan.source_type,
            modules: ['ip-enrichment', 'service-parsing'], // Use modular pipeline
            sinkTypes: nmapPlan.sink_types,
          });
          console.log('Created plan with modules:', nmapPlan);
        }

        plans.push(nmapPlan);
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