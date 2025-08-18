// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
//
// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.
//
// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security
//
//     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
//     License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
//     version.
//
//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
//     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//     details.
//
//     You should have received a copy of the GNU General Public License along with this program.
//     If not, see <http://www.gnu.org/licenses/>.

import { create } from 'zustand';
import { listen, emit } from '@tauri-apps/api/event';

export interface Host {
  id: string;
  ip: string;
  hostname?: string;
  mac_address?: string;
  vendor?: string;
  os_name?: string;
  os_family?: string;
  os_accuracy?: number;
  status: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  port_count: number;
  vulnerability_count: number;
  notes?: string;
  tags: string[];
  scan_progress?: number;
  // Legacy compatibility fields
  timestamp?: string;
}

interface HostStore {
  hosts: Host[];
  ports: Record<string, Set<number>>;
  getHosts: () => Host[];
  getHost: (ip: string) => Host | undefined;
  setHosts: (hosts: Host[]) => void;
  addHost: (host: Host) => void;
}

const useHostStore = create<HostStore>((set, get) => {
  // Listen for host events from the backend and update the store
  listen('obs:host', (event: any) => {
    const hostEvent = event.payload;
    console.log('Received obs:host event:', hostEvent);
    
    // Convert basic HostEvent to partial Host object
    const partialHost: Partial<Host> = {
      ip: hostEvent.ip,
      hostname: hostEvent.hostname,
      id: hostEvent.ip, // Use IP as temporary ID
      status: 'up', // Assume host is up if discovered
      created_at: hostEvent.timestamp,
      updated_at: hostEvent.timestamp,
      last_seen: hostEvent.timestamp,
      port_count: 0,
      vulnerability_count: 0,
      tags: []
    };
    
    set(state => {
      const idx = state.hosts.findIndex(h => h.ip === hostEvent.ip);
      if (idx !== -1) {
        const updated = [...state.hosts];
        updated[idx] = { ...updated[idx], ...partialHost };
        console.log('Updated existing host:', updated[idx]);
        return { hosts: updated };
      }
      console.log('Adding new host:', partialHost);
      return { hosts: [...state.hosts, partialHost as Host] };
    });
  }).catch(console.error);


  // When a service is observed, notify listeners to refresh that host's ports
  listen('obs:service', (event: any) => {
    const serviceEvent = event.payload;
    if (serviceEvent?.ip) {
      console.log('Received obs:service event for', serviceEvent.ip);
      emit('refresh_host_ports', serviceEvent.ip).catch(console.error);
    }
  }).catch(console.error);

  // Listen for refresh signals and fetch detailed host data
  listen('refresh_host_data', async (event: any) => {
    const ip = event.payload as string;
    console.log('Received refresh_host_data event for IP:', ip);
    
    // Add a small delay to allow database to be updated first
    await new Promise(resolve => setTimeout(resolve, 500));
    
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const detailedHost = await invoke<Host>('get_host_by_ip', { ip });
      console.log('Fetched detailed host data:', detailedHost);
      
      set(state => {
        const idx = state.hosts.findIndex(h => h.ip === ip);
        if (idx !== -1) {
          const updated = [...state.hosts];
          updated[idx] = detailedHost;
          console.log('Updated host with detailed data:', updated[idx]);
          return { hosts: updated };
        }
        console.log('Adding new detailed host:', detailedHost);
        return { hosts: [...state.hosts, detailedHost] };
      });
    } catch (error) {
      console.error('Failed to fetch detailed host data for', ip, ':', error);
    }
  }).catch(console.error);

  return {
    hosts: [],
    ports: {},
    getHosts: () => get().hosts,
    getHost: (ip: string) => get().hosts.find(h => h.ip === ip),
    setHosts: (hosts: Host[]) => set({ hosts }),
    addHost: (host: Host) => set(state => ({
      hosts: [...state.hosts.filter(h => h.ip !== host.ip), host]
    })),
  };
});

export default useHostStore;
