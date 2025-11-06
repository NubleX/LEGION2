// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

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
  cancelScan: () => Promise<void>;
  clearOutput: () => void;
  resetScan: () => void;
  loadExistingData: () => Promise<void>;
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
      set((state) => ({
        scanInProgress: false,
        liveOutput: [...state.liveOutput, 'Scan completed. Ready for new scan.']
      }));
    });
  };

  // Initialize listeners and load existing data
  setupEventListeners().catch(console.error);

  // Auto-load existing data on startup
  setTimeout(async () => {
    try {
      const existingHosts = await invoke<any[]>('get_all_hosts');
      if (existingHosts && existingHosts.length > 0) {
        set((state) => ({
          liveOutput: [...state.liveOutput, `Loaded ${existingHosts.length} hosts from previous scans.`],
          metrics: {
            ...state.metrics,
            hosts_discovered: existingHosts.length
          }
        }));
      }
    } catch (error) {
      console.error('Failed to load existing data on startup:', error);
    }
  }, 500); // Small delay to ensure backend is ready

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
      console.log('[appStore] startScan called with config:', config);
      const targets = config.targets;

      // Smart port handling based on scan type:
      // - Quick scan: empty = use nmap's default top 1000 ports (fast host discovery)
      // - Comprehensive scan: empty = all 65535 ports (-p-)
      // - User specified: use exactly what user specified
      let ports = config.ports && config.ports.trim() !== '' ? config.ports : '';
      if (ports === '' && config.scanType === 'comprehensive') {
        ports = '-'; // This tells nmap to use -p- (all ports)
      }
      // For quick scans, empty ports means nmap's default 1000 ports (perfect for fast discovery)

      console.log('[appStore] Processed targets:', targets, 'ports:', ports || '(default 1000)', 'scanType:', config.scanType);

      // Build plans based on selected tools
      const plans: Plan[] = [];

      if (config.useMasscan) {
        // Use Plan::masscan builder method
        const scanId = crypto.randomUUID();
        const masscanPlan = await invoke<Plan>('create_masscan_plan', {
          scanId,
          targets,
          ports,
          rate: config.rate || 1000,
          interface: config.interface,
        });
        plans.push(masscanPlan);
      }

      if (config.useNmap) {
        // Use appropriate Plan builder based on scan type
        let nmapPlan: Plan;
        const scanId = crypto.randomUUID();

        switch (config.scanType) {
          case 'quick':
            // Quick scan: fast, no version detection, normal host discovery
            const quickArgs = ['-T4']; // Fast timing, let nmap do host discovery
            if (config.detectOS) quickArgs.push('-O');
            if (config.skipPing) quickArgs.push('-Pn'); // Only skip ping if user explicitly asks
            // Don't use -sV in quick scans - it's too slow
            // if (config.detectVersions) quickArgs.push('-sV');

            nmapPlan = await invoke<Plan>('create_nmap_plan', {
              scanId,
              targets,
              ports,
              scanType: 'quick',
              extraArgs: quickArgs,
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
            if (config.skipPing) nmapArgs.push('-Pn'); // Only if user explicitly enables
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

        // OS detection is already handled in the comprehensive plan
        // Module system will be implemented later

        plans.push(nmapPlan);
      }

      set((state) => ({
        scanInProgress: true,
        liveOutput: [...state.liveOutput, `Starting scan for ${targets} using ${plans.map(p => p.source_type).join(' & ')}...`],
      }));

      try {
        for (const plan of plans) {
          console.log('Executing scan plan:', plan);
          await invoke('engine_execute', { plan });
          console.log('Plan executed successfully');
        }

        // Don't set scanInProgress to false here - let the backend handle it via obs:done event
        set((state) => ({
          liveOutput: [...state.liveOutput, 'All scan plans submitted to backend.']
        }));
      } catch (error) {
        console.error('Scan execution failed:', error);
        set((state) => ({
          scanInProgress: false,
          liveOutput: [...state.liveOutput, `ERROR: Scan failed - ${error}`]
        }));
        throw error;
      }
    },

    cancelScan: async () => {
      try {
        await invoke('engine_cancel_scan');
        set((state) => ({
          scanInProgress: false,
          liveOutput: [...state.liveOutput, 'Scan cancelled by user.']
        }));
      } catch (error) {
        console.error('Failed to cancel scan:', error);
        set((state) => ({
          liveOutput: [...state.liveOutput, 'ERROR: Failed to cancel scan.']
        }));
      }
    },

    clearOutput: () => {
      set({ liveOutput: [] });
    },

    resetScan: () => {
      set({
        scanInProgress: false,
        liveOutput: ['Previous scan data preserved. Ready for new scan.'],
        // Keep existing data persistent:
        // recentHosts: [],
        // recentServices: [],
        // vulnerabilities: [],
        metrics: {
          hosts_discovered: 0,
          services_discovered: 0,
          processing_rate: 0,
          observations_processed: 0,
        }
      });
    },

    loadExistingData: async () => {
      try {
        // Load existing hosts from database to show persistent data
        const existingHosts = await invoke<any[]>('get_all_hosts');
        if (existingHosts && existingHosts.length > 0) {
          set((state) => ({
            liveOutput: [...state.liveOutput, `Loaded ${existingHosts.length} hosts from previous scans.`],
            metrics: {
              ...state.metrics,
              hosts_discovered: existingHosts.length
            }
          }));
        }
      } catch (error) {
        console.error('Failed to load existing data:', error);
      }
    }
  };
});

export default useAppStore;
