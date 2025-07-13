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

import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';

export interface Host {
  id: string;
  ip: string;
  hostname?: string;
  mac_address?: string;
  os_name?: string;
  os_family?: string;
  os_accuracy?: number;
  status: 'up' | 'down' | 'unknown' | 'scanning';
  last_seen: string;
  created_at: string;
  updated_at: string;
  port_count: number;
  vulnerability_count: number;
}

export interface HostFilter {
  status?: 'up' | 'down' | 'unknown' | 'scanning';
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
  getHostsByStatus: (status: 'up' | 'down' | 'unknown' | 'scanning') => Host[];
  getHostsBySeverity: (severity: 'critical' | 'high') => Host[];
  updateStatistics: () => void;
}

const useHostStore = create<HostStore>((set, get) => ({
  hosts: [],
  filteredHosts: [],
  currentFilter: {},
  isLoading: false,
  lastError: null,

  loadHosts: async () => {
    set({ isLoading: true, lastError: null });
    
    try {
      const hosts = await invoke('get_all_hosts') as Host[];
      
      set({ 
        hosts: hosts,
        filteredHosts: hosts,
        isLoading: false 
      });
    } catch (error) {
      console.error('Failed to load hosts:', error);
      // Fall back to empty array instead of mock data
      set({ 
        hosts: [],
        filteredHosts: [],
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

  exportHosts: async () => {
    return JSON.stringify(get().filteredHosts, null, 2);
  },

  deleteMultipleHosts: async (hostIds: string[]) => {
    const hosts = get().hosts.filter(h => !hostIds.includes(h.id));
    set({ hosts, filteredHosts: hosts });
  },

  refreshHost: async (hostId: string) => {
    console.log('Refreshing host:', hostId);
  },

  getHostsByStatus: (status: 'up' | 'down' | 'unknown' | 'scanning') => {
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