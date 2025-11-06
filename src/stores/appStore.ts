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
  pendingScans: number; // Track number of pending scans in multi-scan sequences
}

interface AppActions {
  // Simple actions
  startScan: (config: ScanConfig) => Promise<void>;
  cancelScan: () => Promise<void>;
  clearOutput: () => void;
  resetScan: () => void;
  loadExistingData: () => Promise<void>;
  startNetsniffer: (iface?: string) => Promise<void>;
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
      set((state) => {
        const newPendingScans = Math.max(0, (state.pendingScans || 0) - 1);
        const allScansDone = newPendingScans === 0;
        
        return {
          pendingScans: newPendingScans,
          scanInProgress: !allScansDone, // Only set to false when all scans are done
          liveOutput: allScansDone 
            ? [...state.liveOutput, 'All scans completed. Ready for new scan.']
            : [...state.liveOutput, 'Scan phase completed. Continuing...']
        };
      });
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
    pendingScans: 0,

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

      // Use massmap - unified scanner that intelligently uses masscan + nmap
      const scanId = crypto.randomUUID();
      
      // Parse extra args
      const extraArgs = config.extra ? config.extra.split(' ').filter(a => a.trim()) : [];
      
      const massmapResult = await invoke<{
        use_masscan: boolean;
        masscan_plan: Plan | null;
        nmap_plan: Plan;
      }>('create_massmap_plan', {
        scanId,
        targets,
        ports,
        scanType: config.scanType,
        extraArgs,
        detectOs: config.detectOS,
        detectVersions: config.detectVersions,
        skipPing: config.skipPing,
        rate: config.rate || 1000,
        interface: config.interface || null,
      });

      // Build plans to execute sequentially
      const plans: Plan[] = [];
      
      // If masscan is needed, add it first
      if (massmapResult.use_masscan && massmapResult.masscan_plan) {
        plans.push(massmapResult.masscan_plan);
      }
      
      // Always add nmap plan for detailed scanning
      plans.push(massmapResult.nmap_plan);

      set((state) => ({
        scanInProgress: true,
        pendingScans: plans.length, // Track total number of scans
        liveOutput: [...state.liveOutput, `Starting scan for ${targets} using ${plans.map(p => p.source_type).join(' & ')}...`],
      }));

      try {
        // Helper function to wait for scan completion
        const waitForScanCompletion = async (scanId: string): Promise<void> => {
          return new Promise(async (resolve, reject) => {
            // Set up a timeout to prevent infinite waiting
            let timeout: NodeJS.Timeout | null = null;
            let unlistenFn: (() => void) | null = null;

            try {
              // Listen for obs:done event
              unlistenFn = await listen('obs:done', () => {
                if (timeout) clearTimeout(timeout);
                if (unlistenFn) unlistenFn();
                resolve();
              });

              // Set up timeout
              timeout = setTimeout(() => {
                if (unlistenFn) unlistenFn();
                reject(new Error(`Scan ${scanId} timed out after 30 minutes`));
              }, 30 * 60 * 1000); // 30 minutes timeout
            } catch (error) {
              if (timeout) clearTimeout(timeout);
              if (unlistenFn) unlistenFn();
              reject(error);
            }
          });
        };

        // Execute plans sequentially, waiting for each to complete
        for (let i = 0; i < plans.length; i++) {
          const plan = plans[i];
          const isLastPlan = i === plans.length - 1;
          
          console.log('Executing scan plan:', plan);
          set((state) => ({
            liveOutput: [...state.liveOutput, `Starting ${plan.source_type} scan...`]
          }));

          // Set up completion listener BEFORE starting the scan (to avoid race condition)
          let completionPromise: Promise<void> | null = null;
          if (!isLastPlan) {
            console.log(`Setting up completion listener for ${plan.source_type} scan...`);
            completionPromise = waitForScanCompletion(plan.scan_id);
          }

          // Execute the plan
          await invoke('engine_execute', { plan });
          
          // Wait for this scan to complete before proceeding (except for the last one)
          if (!isLastPlan && completionPromise) {
            console.log(`Waiting for ${plan.source_type} scan to complete before starting next scan...`);
            set((state) => ({
              liveOutput: [...state.liveOutput, `Waiting for ${plan.source_type} to complete...`]
            }));
            
            try {
              await completionPromise;
              console.log(`${plan.source_type} scan completed successfully`);
              set((state) => ({
                liveOutput: [...state.liveOutput, `${plan.source_type} scan completed. Starting next phase...`]
              }));
            } catch (error) {
              console.error(`Failed to wait for ${plan.source_type} completion:`, error);
              set((state) => ({
                liveOutput: [...state.liveOutput, `Warning: ${plan.source_type} scan completion check failed, continuing anyway...`]
              }));
              // Continue anyway - don't block the next scan if wait fails
            }
          } else {
            console.log('Plan executed successfully (last plan, no wait needed)');
          }
        }

        // Don't set scanInProgress to false here - let the backend handle it via obs:done event from the last scan
        set((state) => ({
          liveOutput: [...state.liveOutput, 'All scan plans submitted and executed.']
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
        pendingScans: 0,
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
    },

    startNetsniffer: async (iface?: string) => {
      try {
        const scanId = crypto.randomUUID();
        const interfaceName = iface || 'default';
        
        console.log('[appStore] Starting netsniffer with interface:', interfaceName);
        
        set((state) => ({
          liveOutput: [...state.liveOutput, `Starting network sniffer on interface: ${interfaceName}...`]
        }));

        // Create netsniffer plan
        const plan = await invoke<Plan>('create_netsniffer_plan', {
          scanId,
          interface: interfaceName,
        });

        console.log('[appStore] Created netsniffer plan:', plan);

        // Execute the plan via engine
        await invoke('engine_execute', { plan });

        set((state) => ({
          liveOutput: [...state.liveOutput, 'Network sniffer started. Monitoring network traffic and enriching knowledgebase...']
        }));
      } catch (error) {
        console.error('Failed to start netsniffer:', error);
        set((state) => ({
          liveOutput: [...state.liveOutput, `ERROR: Failed to start network sniffer - ${error}`]
        }));
        throw error;
      }
    }
  };
});

export default useAppStore;
