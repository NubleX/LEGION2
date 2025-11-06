// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { emit, listen } from '@tauri-apps/api/event';
import { create } from 'zustand';

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
      mac_address: hostEvent.mac, // Backend emits 'mac', we store as 'mac_address'
      vendor: hostEvent.vendor,
      os_name: hostEvent.os, // Backend emits 'os', we store as 'os_name'
      status: hostEvent.status,
      id: hostEvent.ip, // Use IP as temporary ID
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

    // Add delay to allow database batch to be flushed (5 second batch interval)
    await new Promise(resolve => setTimeout(resolve, 6000));

    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const detailedHost = await invoke<Host>('get_host_by_ip', { ip });
      console.log('Fetched detailed host data:', detailedHost);

      set(state => {
        const idx = state.hosts.findIndex(h => h.ip === ip);
        if (idx !== -1) {
          const updated = [...state.hosts];
          const existing = updated[idx];
          // Smart merge: only update fields that are non-null in detailedHost
          // This prevents overwriting good live data with stale null values from DB
          updated[idx] = {
            ...existing,
            // Only update if new value is not null/undefined
            hostname: detailedHost.hostname ?? existing.hostname,
            mac_address: detailedHost.mac_address ?? existing.mac_address,
            vendor: detailedHost.vendor ?? existing.vendor,
            os_name: detailedHost.os_name ?? existing.os_name,
            os_family: detailedHost.os_family ?? existing.os_family,
            os_accuracy: detailedHost.os_accuracy ?? existing.os_accuracy,
            // Always update these from DB (they should be most current)
            // EXCEPT status - trust live events over DB for status (DB may have stale data)
            status: existing.status === 'up' ? existing.status : detailedHost.status,
            port_count: detailedHost.port_count,
            vulnerability_count: detailedHost.vulnerability_count,
            last_seen: detailedHost.last_seen,
            updated_at: detailedHost.updated_at,
            notes: detailedHost.notes ?? existing.notes,
            tags: detailedHost.tags.length > 0 ? detailedHost.tags : existing.tags,
            scan_progress: detailedHost.scan_progress ?? existing.scan_progress,
          };
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
