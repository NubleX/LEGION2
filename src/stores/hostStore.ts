// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { create } from 'zustand';

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

export interface HostFilter {
  status?: 'up' | 'down' | 'unknown';
  os_family?: string;
  has_vulnerabilities?: boolean;
  port_range?: { min: number; max: number };
  severity_min?: 'low' | 'medium' | 'high' | 'critical';
  search_term?: string;
}

interface HostStore {
  hosts: Host[];
  filteredHosts: Host[];
  currentFilter: HostFilter;
  isLoading: boolean;
  lastError: string | null;
  
  loadHosts: () => Promise<void>;
  setFilter: (filter: HostFilter) => void;
  clearFilter: () => void;
  searchHosts: (term: string) => void;
  deleteHost: (hostId: string) => Promise<void>;
  loadHostDetails: (hostId: string) => Promise<void>;
  exportHosts: (format: 'json' | 'csv' | 'xml') => Promise<string>;
  deleteMultipleHosts: (hostIds: string[]) => Promise<void>;
  refreshHost: (hostId: string) => Promise<void>;
  getHostsByStatus: (status: 'up' | 'down' | 'unknown') => Host[];
  getHostsBySeverity: (severity: 'critical' | 'high') => Host[];
  updateStatistics: () => void;
}

// Mock data for testing layout
const mockHosts: Host[] = [
  {
    id: '1',
    ip: '192.168.1.1',
    hostname: 'router.local',
    os_name: 'Linux',
    os_family: 'Linux',
    os_accuracy: 95,
    status: 'up',
    last_seen: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    port_count: 5,
    vulnerability_count: 2
  },
  {
    id: '2', 
    ip: '192.168.1.100',
    hostname: 'workstation',
    os_name: 'Windows 10',
    os_family: 'Windows',
    os_accuracy: 87,
    status: 'up',
    last_seen: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    port_count: 12,
    vulnerability_count: 7
  },
  {
    id: '3',
    ip: '192.168.1.50',
    hostname: 'server.local',
    os_name: 'Ubuntu 22.04',
    os_family: 'Linux',
    os_accuracy: 99,
    status: 'up',
    last_seen: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    port_count: 8,
    vulnerability_count: 0
  }
];

const useHostStore = create<HostStore>((set, get) => ({
  hosts: [],
  filteredHosts: [],
  currentFilter: {},
  isLoading: false,
  lastError: null,

  loadHosts: async () => {
    set({ isLoading: true, lastError: null });
    
    try {
      // Simulate loading delay
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // Use mock data for now
      set({ 
        hosts: mockHosts,
        filteredHosts: mockHosts,
        isLoading: false 
      });
    } catch (error) {
      set({ 
        lastError: `Failed to load hosts: ${error}`,
        isLoading: false 
      });
    }
  },

  setFilter: (filter: HostFilter) => {
    const hosts = get().hosts;
    let filtered = hosts;

    if (filter.status) {
      filtered = filtered.filter(h => h.status === filter.status);
    }
    if (filter.search_term) {
      const term = filter.search_term.toLowerCase();
      filtered = filtered.filter(h => 
        h.ip.includes(term) || 
        h.hostname?.toLowerCase().includes(term) ||
        h.os_name?.toLowerCase().includes(term)
      );
    }
    if (filter.has_vulnerabilities) {
      filtered = filtered.filter(h => h.vulnerability_count > 0);
    }

    set({ currentFilter: filter, filteredHosts: filtered });
  },

  clearFilter: () => {
    set({ 
      currentFilter: {},
      filteredHosts: get().hosts 
    });
  },

  searchHosts: (term: string) => {
    get().setFilter({ ...get().currentFilter, search_term: term });
  },

  deleteHost: async (hostId: string) => {
    const hosts = get().hosts.filter(h => h.id !== hostId);
    set({ hosts, filteredHosts: hosts });
  },

  loadHostDetails: async (hostId: string) => {
    console.log('Loading details for host:', hostId);
  },

  exportHosts: async (format: string) => {
    return JSON.stringify(get().filteredHosts, null, 2);
  },

  deleteMultipleHosts: async (hostIds: string[]) => {
    const hosts = get().hosts.filter(h => !hostIds.includes(h.id));
    set({ hosts, filteredHosts: hosts });
  },

  refreshHost: async (hostId: string) => {
    console.log('Refreshing host:', hostId);
  },

  getHostsByStatus: (status: 'up' | 'down' | 'unknown') => {
    return get().hosts.filter(h => h.status === status);
  },

  getHostsBySeverity: (severity: 'critical' | 'high') => {
    if (severity === 'critical') {
      return get().hosts.filter(h => h.vulnerability_count >= 10);
    }
    return get().hosts.filter(h => h.vulnerability_count >= 5);
  },

  updateStatistics: () => {
    // Update stats logic here
  }
}));

export default useHostStore;