// src/export/stores/legionStore.ts - Minimal integration with existing stores
import { create } from 'zustand';
import { legionService } from '../../services/tauriApi';

// Simple interfaces to avoid conflicts with your existing types
interface SimpleScanResult {
  id: string;
  target_id: string;
  status: string;
  scan_type: string;
}

interface SimpleHost {
  id: string;
  ip: string;
  hostname?: string;
  status: string;
}

interface SimpleVulnerability {
  id: string;
  name: string;
  severity: string;
  description: string;
}

interface SimpleProject {
  id: string;
  name: string;
  description?: string;
  created_at: string;
}

interface SimpleStatistics {
  total_scans: number;
  active_scans: number;
  hosts_discovered: number;
  vulnerabilities_found: number;
}

interface LegionStore {
  // Scan state
  scanResults: SimpleScanResult[];
  activeScanIds: Set<string>;
  isScanning: boolean;
  scanProgress: Map<string, number>;
  
  // Host and vulnerability data
  hosts: SimpleHost[];
  vulnerabilities: SimpleVulnerability[];
  
  // Project management
  projects: SimpleProject[];
  currentProject?: SimpleProject;
  
  // Statistics
  statistics: SimpleStatistics | null;

  // Actions
  startScan: (targetIp: string, scanType: string) => Promise<string>;
  cancelScan: (scanId: string) => Promise<void>;
  refreshScanResults: () => Promise<void>;
  refreshHosts: () => Promise<void>;
  refreshVulnerabilities: (severityFilter?: string) => Promise<void>;
  refreshProjects: () => Promise<void>;
  refreshStatistics: () => Promise<void>;
  updateScanProgress: (scanId: string, progress: number) => void;
  createProject: (name: string, description?: string) => Promise<void>;
  setCurrentProject: (project: SimpleProject) => void;
}

export const useLegionStore = create<LegionStore>((set, get) => ({
  // Initial state
  scanResults: [],
  activeScanIds: new Set(),
  isScanning: false,
  scanProgress: new Map(),
  hosts: [],
  vulnerabilities: [],
  projects: [],
  currentProject: undefined,
  statistics: null,

  // Start scan
  startScan: async (targetIp: string, scanType: string) => {
    try {
      const scanId = await legionService.startScan(targetIp, scanType);
      
      // Set up progress listener
      legionService.onScanProgress(scanId, (progress) => {
        const progressValue = progress?.progress || 0;
        get().updateScanProgress(scanId, progressValue);
      });

      set((state) => ({
        activeScanIds: new Set([...state.activeScanIds, scanId]),
        isScanning: true,
      }));

      return scanId;
    } catch (error) {
      console.error('Failed to start scan:', error);
      throw error;
    }
  },

  cancelScan: async (scanId: string) => {
    try {
      await legionService.cancelScan(scanId);
      legionService.removeScanListener(scanId);
      
      set((state) => {
        const newActiveScanIds = new Set(state.activeScanIds);
        newActiveScanIds.delete(scanId);
        
        const newProgress = new Map(state.scanProgress);
        newProgress.delete(scanId);
        
        return {
          activeScanIds: newActiveScanIds,
          isScanning: newActiveScanIds.size > 0,
          scanProgress: newProgress,
        };
      });
    } catch (error) {
      console.error('Failed to cancel scan:', error);
      throw error;
    }
  },

  refreshScanResults: async () => {
    try {
      const results = await legionService.getScanResults();
      set({ scanResults: results });
    } catch (error) {
      console.error('Failed to refresh scan results:', error);
    }
  },

  refreshHosts: async () => {
    try {
      const hosts = await legionService.getHosts();
      set({ hosts });
    } catch (error) {
      console.error('Failed to refresh hosts:', error);
    }
  },

  refreshVulnerabilities: async (severityFilter?: string) => {
    try {
      const vulnerabilities = await legionService.getVulnerabilities(severityFilter);
      set({ vulnerabilities });
    } catch (error) {
      console.error('Failed to refresh vulnerabilities:', error);
    }
  },

  refreshProjects: async () => {
    try {
      const projects = await legionService.listProjects();
      set({ projects });
    } catch (error) {
      console.error('Failed to refresh projects:', error);
    }
  },

  refreshStatistics: async () => {
    try {
      const statistics = await legionService.getScanStatistics();
      set({ statistics });
    } catch (error) {
      console.error('Failed to refresh statistics:', error);
    }
  },

  updateScanProgress: (scanId: string, progress: number) => {
    set((state) => {
      const newProgress = new Map(state.scanProgress);
      newProgress.set(scanId, progress);
      return { scanProgress: newProgress };
    });
  },

  createProject: async (name: string, description?: string) => {
    try {
      const project = await legionService.createProject(name, description);
      set((state) => ({
        projects: [...state.projects, project],
        currentProject: project,
      }));
    } catch (error) {
      console.error('Failed to create project:', error);
      throw error;
    }
  },

  setCurrentProject: (project: SimpleProject) => {
    set({ currentProject: project });
  },
}));