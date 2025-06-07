import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/tauri';

export interface Host {
  id: string;
  ip: string;
  hostname?: string;
  mac_address?: string;
  os_name?: string;
  os_family?: string;
  os_accuracy?: number;
  status: 'up' | 'down' | 'unknown';
  last_seen: string;
  created_at: string;
  updated_at: string;
  port_count: number;
  vulnerability_count: number;
}

export interface HostPort {
  id: string;
  host_id: string;
  number: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
  banner?: string;
  confidence?: number;
  discovered_at: string;
}

export interface HostVulnerability {
  id: string;
  host_id: string;
  port_id?: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  cvss_score?: number;
  references?: string[];
  discovered_at: string;
}

export interface HostDetails {
  host: Host;
  ports: HostPort[];
  vulnerabilities: HostVulnerability[];
}

export interface HostFilter {
  status?: 'up' | 'down' | 'unknown';
  os_family?: string;
  has_vulnerabilities?: boolean;
  port_range?: { min: number; max: number };
  severity_min?: 'low' | 'medium' | 'high' | 'critical';
  search_term?: string;
}

interface HostStore {
  // State
  hosts: Host[];
  selectedHost: HostDetails | null;
  filteredHosts: Host[];
  currentFilter: HostFilter;
  isLoading: boolean;
  lastError: string | null;
  
  // Statistics
  totalHosts: number;
  upHosts: number;
  hostsWithVulnerabilities: number;
  criticalVulnerabilities: number;
  
  // Actions
  loadHosts: () => Promise<void>;
  loadHostDetails: (hostId: string) => Promise<void>;
  refreshHost: (hostId: string) => Promise<void>;
  deleteHost: (hostId: string) => Promise<void>;
  
  // Filtering and search
  setFilter: (filter: HostFilter) => void;
  clearFilter: () => void;
  searchHosts: (term: string) => void;
  
  // Bulk operations
  deleteMultipleHosts: (hostIds: string[]) => Promise<void>;
  exportHosts: (format: 'json' | 'csv' | 'xml') => Promise<string>;
  
  // Utilities
  getHostsByStatus: (status: 'up' | 'down' | 'unknown') => Host[];
  getHostsBySeverity: (severity: 'critical' | 'high') => Host[];
  updateStatistics: () => void;
}

const useHostStore = create<HostStore>((set, get) => ({
  // Initial state
  hosts: [],
  selectedHost: null,
  filteredHosts: [],
  currentFilter: {},
  isLoading: false,
  lastError: null,
  
  // Statistics
  totalHosts: 0,
  upHosts: 0,
  hostsWithVulnerabilities: 0,
  criticalVulnerabilities: 0,

  // Load all hosts from backend
  loadHosts: async () => {
    set({ isLoading: true, lastError: null });
    
    try {
      const hosts = await invoke<Host[]>('get_hosts');
      
      set(state => ({
        hosts,
        filteredHosts: applyFilter(hosts, state.currentFilter),
        isLoading: false,
      }));
      
      get().updateStatistics();
    } catch (error) {
      set({ 
        lastError: String(error),
        isLoading: false 
      });
    }
  },

  // Load detailed information for a specific host
  loadHostDetails: async (hostId: string) => {
    set({ isLoading: true, lastError: null });
    
    try {
      const hostDetails = await invoke<HostDetails>('get_host_details', { hostId });
      
      set({ 
        selectedHost: hostDetails,
        isLoading: false 
      });
    } catch (error) {
      set({ 
        lastError: String(error),
        isLoading: false 
      });
    }
  },

  // Refresh a single host's data
  refreshHost: async (hostId: string) => {
    try {
      const hostDetails = await invoke<HostDetails>('get_host_details', { hostId });
      
      set(state => {
        const updatedHosts = state.hosts.map(host => 
          host.id === hostId ? hostDetails.host : host
        );
        
        return {
          hosts: updatedHosts,
          filteredHosts: applyFilter(updatedHosts, state.currentFilter),
          selectedHost: state.selectedHost?.host.id === hostId ? hostDetails : state.selectedHost,
        };
      });
      
      get().updateStatistics();
    } catch (error) {
      set({ lastError: error as string });
    }
  },

  // Delete a host
  deleteHost: async (hostId: string) => {
    try {
      await invoke('delete_host', { hostId });
      
      set(state => {
        const updatedHosts = state.hosts.filter(host => host.id !== hostId);
        
        return {
          hosts: updatedHosts,
          filteredHosts: applyFilter(updatedHosts, state.currentFilter),
          selectedHost: state.selectedHost?.host.id === hostId ? null : state.selectedHost,
        };
      });
      
      get().updateStatistics();
    } catch (error) {
      set({ lastError: error as string });
      throw error;
    }
  },

  // Set filter criteria
  setFilter: (filter: HostFilter) => {
    set(state => ({
      currentFilter: filter,
      filteredHosts: applyFilter(state.hosts, filter),
    }));
  },

  // Clear all filters
  clearFilter: () => {
    set(state => ({
      currentFilter: {},
      filteredHosts: state.hosts,
    }));
  },

  // Search hosts by IP, hostname, or other criteria
  searchHosts: (term: string) => {
    set(state => {
      const searchFilter = { ...state.currentFilter, search_term: term };
      return {
        currentFilter: searchFilter,
        filteredHosts: applyFilter(state.hosts, searchFilter),
      };
    });
  },

  // Delete multiple hosts
  deleteMultipleHosts: async (hostIds: string[]) => {
    try {
      await invoke('delete_multiple_hosts', { hostIds });
      
      set(state => {
        const updatedHosts = state.hosts.filter(host => !hostIds.includes(host.id));
        
        return {
          hosts: updatedHosts,
          filteredHosts: applyFilter(updatedHosts, state.currentFilter),
          selectedHost: hostIds.includes(state.selectedHost?.host.id || '') ? null : state.selectedHost,
        };
      });
      
      get().updateStatistics();
    } catch (error) {
      set({ lastError: error as string });
      throw error;
    }
  },

  // Export hosts in various formats
  exportHosts: async (format: 'json' | 'csv' | 'xml') => {
    try {
      const data = await invoke<string>('export_hosts', { 
        format,
        hostIds: get().filteredHosts.map(h => h.id)
      });
      return data;
    } catch (error) {
      set({ lastError: error as string });
      throw error;
    }
  },

  // Get hosts by status
  getHostsByStatus: (status: 'up' | 'down' | 'unknown') => {
    return get().hosts.filter(host => host.status === status);
  },

// Get hosts with high/critical vulnerabilities
  getHostsBySeverity: () => {
    return get().hosts.filter(host => host.vulnerability_count > 0);
  },

  // Update statistics based on current host data
  updateStatistics: () => {
    set(state => {
      const upHosts = state.hosts.filter(h => h.status === 'up').length;
      const hostsWithVulns = state.hosts.filter(h => h.vulnerability_count > 0).length;
      
      // This is a simplified calculation - in reality, you'd get this from the backend
      const criticalVulns = state.hosts.reduce((sum, host) => sum + host.vulnerability_count, 0);
      
      return {
        totalHosts: state.hosts.length,
        upHosts,
        hostsWithVulnerabilities: hostsWithVulns,
        criticalVulnerabilities: criticalVulns,
      };
    });
  },
}));

// Helper function to apply filters to host list
function applyFilter(hosts: Host[], filter: HostFilter): Host[] {
  return hosts.filter(host => {
    // Status filter
    if (filter.status && host.status !== filter.status) {
      return false;
    }
    
    // OS family filter
    if (filter.os_family && host.os_family !== filter.os_family) {
      return false;
    }
    
    // Vulnerability filter
    if (filter.has_vulnerabilities !== undefined) {
      const hasVulns = host.vulnerability_count > 0;
      if (filter.has_vulnerabilities !== hasVulns) {
        return false;
      }
    }
    
    // Port range filter
    if (filter.port_range && host.port_count) {
      const { min, max } = filter.port_range;
      if (host.port_count < min || host.port_count > max) {
        return false;
      }
    }
    
    // Search term filter
    if (filter.search_term) {
      const term = filter.search_term.toLowerCase();
      const searchable = [
        host.ip,
        host.hostname,
        host.os_name,
        host.mac_address
      ].filter(Boolean).join(' ').toLowerCase();
      
      if (!searchable.includes(term)) {
        return false;
      }
    }
    
    return true;
  });
}

export { useHostStore };
export default useHostStore;