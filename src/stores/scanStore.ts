import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import type { ScanTarget, ScanProgress, ScanResult, ScanStatistics } from '../types/scanning';

interface ScanStore {
  // State
  activeScans: Map<string, ScanResult>;
  scanHistory: ScanResult[];
  currentProgress: Map<string, ScanProgress>;
  statistics: ScanStatistics;
  isScanning: boolean;
  lastError: string | null;
  
  // Actions
  startScan: (target: ScanTarget) => Promise<string>;
  cancelScan: (scanId: string) => Promise<void>;
  stopScan: () => Promise<void>;
  cancelAllScans: () => Promise<void>;
  scanNetworkRange: (cidr: string, excludes: string[], scanType: string) => Promise<string[]>;
  
  // Progress tracking
  updateProgress: (progress: ScanProgress) => void;
  updateScanResult: (result: ScanResult) => void;
  
  // Data management
  clearHistory: () => void;
  refreshStatistics: () => Promise<void>;
  getScanById: (scanId: string) => ScanResult | undefined;
  
  // Event listeners
  initializeEventListeners: () => Promise<void>;
  cleanupEventListeners: () => void;
}

const useScanStore = create<ScanStore>((set, get) => ({
  // Initial state
  activeScans: new Map(),
  scanHistory: [],
  currentProgress: new Map(),
  statistics: {
    total_scans: 0,
    active_scans: 0,
    completed_scans: 0,
    failed_scans: 0,
    total_hosts_discovered: 0,
    total_ports_discovered: 0,
    total_vulnerabilities: 0,
    scan_time_total: 0,
    avg_scan_duration: 0,
  },
  isScanning: false,
  lastError: null,

  // Start a new scan
  startScan: async (target: ScanTarget) => {
    try {
      set({ lastError: null, isScanning: true });
      
      const scanId = await invoke<string>('start_scan', { target });
      
      const newScan: ScanResult = {
        id: scanId,
        target_id: target.id,
        status: 'queued',
        start_time: new Date().toISOString(),
        open_ports: [],
        vulnerabilities: [],
        scan_type: target.scan_type,
      };

      set(state => ({
        activeScans: new Map(state.activeScans).set(scanId, newScan),
        statistics: {
          ...state.statistics,
          total_scans: state.statistics.total_scans + 1,
          active_scans: state.statistics.active_scans + 1,
        }
      }));

      return scanId;
    } catch (error) {
      set({ 
        lastError: String(error),
        isScanning: false 
      });
      throw error;
    }
  },

  // Cancel a specific scan
  cancelScan: async (scanId: string) => {
    try {
      await invoke('cancel_scan', { scanId });
      
      set(state => {
        const updatedScans = new Map(state.activeScans);
        const scan = updatedScans.get(scanId);
        if (scan) {
          const updatedScan: ScanResult = {
            ...scan,
            status: 'cancelled',
            end_time: new Date().toISOString(),
          };
          updatedScans.set(scanId, updatedScan);
        }
        
        return {
          activeScans: updatedScans,
          statistics: {
            ...state.statistics,
            active_scans: Math.max(0, state.statistics.active_scans - 1),
          }
        };
      });
    } catch (error) {
      set({ lastError: error as string });
      throw error;
    }
  },

  // Stop current scan (alias for cancelScan for compatibility)
  stopScan: async () => {
    const activeScansArray = Array.from(get().activeScans.keys());
    if (activeScansArray.length > 0) {
      await get().cancelScan(activeScansArray[0]);
    }
  },
  cancelAllScans: async () => {
    try {
      await invoke('cancel_all_scans');
      
      set(state => {
        const updatedScans = new Map();
        const currentTime = new Date().toISOString();
        
        state.activeScans.forEach((scan, id) => {
          if (scan.status === 'running' || scan.status === 'queued') {
            const updatedScan: ScanResult = {
              ...scan,
              status: 'cancelled',
              end_time: currentTime,
            };
            updatedScans.set(id, updatedScan);
          } else {
            updatedScans.set(id, scan);
          }
        });

        return {
          activeScans: updatedScans,
          isScanning: false,
          statistics: {
            ...state.statistics,
            active_scans: 0,
          }
        };
      });
    } catch (error) {
      set({ lastError: error as string });
      throw error;
    }
  },

  // Scan network range
  scanNetworkRange: async (cidr: string, excludes: string[], scanType: string) => {
    try {
      set({ lastError: null, isScanning: true });
      
      const scanIds = await invoke<string[]>('scan_network_range', {
        range: { cidr, exclude: excludes, scan_type: scanType }
      });

      // Add all network scans to active scans
      set(state => {
        const updatedScans = new Map(state.activeScans);
        
        scanIds.forEach(scanId => {
          const newScan: ScanResult = {
            id: scanId,
            target_id: `network-${scanId}`,
            status: 'queued',
            start_time: new Date().toISOString(),
            open_ports: [],
            vulnerabilities: [],
            scan_type: scanType,
          };
          updatedScans.set(scanId, newScan);
        });

        return {
          activeScans: updatedScans,
          statistics: {
            ...state.statistics,
            total_scans: state.statistics.total_scans + scanIds.length,
            active_scans: state.statistics.active_scans + scanIds.length,
          }
        };
      });

      return scanIds;
    } catch (error) {
      set({ 
        lastError: error as string,
        isScanning: false 
      });
      throw error;
    }
  },

  // Update scan progress
  updateProgress: (progress: ScanProgress) => {
    set(state => ({
      currentProgress: new Map(state.currentProgress).set(progress.scan_id, progress)
    }));
  },

  // Update scan result
  updateScanResult: (result: ScanResult) => {
    set(state => {
      const updatedScans = new Map(state.activeScans);
      updatedScans.set(result.id, result);

      // Move completed scans to history
      const newHistory = [...state.scanHistory];
      if (result.status === 'completed' || result.status === 'failed' || result.status === 'cancelled') {
        const existingIndex = newHistory.findIndex(scan => scan.id === result.id);
        if (existingIndex >= 0) {
          newHistory[existingIndex] = result;
        } else {
          newHistory.push(result);
        }
        updatedScans.delete(result.id);
      }

      // Update scanning status
      const hasActiveScans = Array.from(updatedScans.values()).some(
        scan => scan.status === 'running' || scan.status === 'queued'
      );

      return {
        activeScans: updatedScans,
        scanHistory: newHistory,
        isScanning: hasActiveScans,
        statistics: {
          ...state.statistics,
          active_scans: updatedScans.size,
          completed_scans: newHistory.filter(s => s.status === 'completed').length,
          failed_scans: newHistory.filter(s => s.status === 'failed').length,
        }
      };
    });
  },

  // Clear scan history
  clearHistory: () => {
    set({ scanHistory: [] });
  },

  // Refresh statistics from backend
  refreshStatistics: async () => {
    try {
      const stats = await invoke<ScanStatistics>('get_scan_statistics');
      set({ statistics: stats });
    } catch (error) {
      set({ lastError: error as string });
    }
  },

  // Get scan by ID
  getScanById: (scanId: string) => {
    const state = get();
    return state.activeScans.get(scanId) || 
           state.scanHistory.find(scan => scan.id === scanId);
  },

  // Initialize event listeners for real-time updates
  initializeEventListeners: async () => {
    // Listen for scan progress updates
    await listen('scan-progress', (event: any) => {
      const progress = event.payload as ScanProgress;
      get().updateProgress(progress);
    });

    // Listen for scan result updates
    await listen('scan-result', (event: any) => {
      const result = event.payload as ScanResult;
      get().updateScanResult(result);
    });

    // Listen for scan completion
    await listen('scan-completed', (event: any) => {
      const result = event.payload as ScanResult;
      get().updateScanResult(result);
    });

    // Listen for scan errors
    await listen('scan-error', (event: any) => {
      const { scanId, error } = event.payload;
      const scan = get().getScanById(scanId);
      if (scan) {
        get().updateScanResult({
          ...scan,
          status: 'failed',
          error_message: error,
          end_time: new Date().toISOString(),
        });
      }
    });
  },

  // Cleanup event listeners
  cleanupEventListeners: () => {
    // Tauri event listeners are automatically cleaned up when component unmounts
    // This is here for future extensibility
  },
}));

export { useScanStore };
export default useScanStore;