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

/**
 * Compares critical host fields to determine if an update is needed.
 * Treats undefined/null/empty new values as "no change" (preserves existing).
 * Returns true if there are actual changes, false if values are identical.
 */
function hasHostDataChanged(existing: Host, incoming: Partial<Host>): boolean {
  // Compare critical fields
  const fieldsToCompare: (keyof Host)[] = [
    'hostname',
    'vendor',
    'os_name',
    'os_family',
    'mac_address',
    'status'
  ];

  for (const field of fieldsToCompare) {
    const existingValue = existing[field];
    const incomingValue = incoming[field];

    // If incoming value is undefined/null/empty, treat as no change
    if (incomingValue === undefined || incomingValue === null || incomingValue === '') {
      continue;
    }

    // If values are different, we have a change
    if (existingValue !== incomingValue) {
      return true;
    }
  }

  // No meaningful changes detected
  return false;
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
        const existing = state.hosts[idx];
        
        // Check if data has actually changed before updating
        if (!hasHostDataChanged(existing, partialHost)) {
          console.log('No changes detected for host', hostEvent.ip, '- skipping update');
          return state; // No changes, skip update entirely
        }
        
        const updated = [...state.hosts];
        // Merge: preserve existing hostname/vendor/OS when new values are undefined
        // This prevents overwriting existing good data with undefined
        // Only update fields that are actually provided (not undefined)
        updated[idx] = {
          ...existing,
          // Update provided fields, but preserve existing values for critical fields when undefined
          ...(partialHost.ip && { ip: partialHost.ip }),
          ...(partialHost.status !== undefined && { status: partialHost.status }),
          ...(partialHost.id !== undefined && { id: partialHost.id }),
          ...(partialHost.created_at !== undefined && { created_at: partialHost.created_at }),
          ...(partialHost.updated_at !== undefined && { updated_at: partialHost.updated_at }),
          ...(partialHost.last_seen !== undefined && { last_seen: partialHost.last_seen }),
          ...(partialHost.tags !== undefined && { tags: partialHost.tags }),
          // Smart merge for critical fields: preserve existing if new value is undefined
          hostname: partialHost.hostname !== undefined ? partialHost.hostname : existing.hostname,
          vendor: partialHost.vendor !== undefined ? partialHost.vendor : existing.vendor,
          os_name: partialHost.os_name !== undefined ? partialHost.os_name : existing.os_name,
          mac_address: partialHost.mac_address !== undefined ? partialHost.mac_address : existing.mac_address,
          // Preserve port_count and vulnerability_count - these come from DB, not host events
          port_count: existing.port_count,
          vulnerability_count: existing.vulnerability_count,
        };
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
          const existing = state.hosts[idx];
          
          // Check if critical host data has changed before updating
          if (!hasHostDataChanged(existing, detailedHost)) {
            // Even if critical fields haven't changed, we might need to update port_count/vulnerability_count
            // Check if these counts have changed
            if (existing.port_count === detailedHost.port_count && 
                existing.vulnerability_count === detailedHost.vulnerability_count) {
              console.log('No changes detected for host', ip, '- skipping update');
              return state; // No changes, skip update entirely
            }
          }
          
          const updated = [...state.hosts];
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

  // Listen for periodic refresh of all hosts from backend
  listen('refresh_all_hosts', async () => {
    console.log('[hostStore] Received refresh_all_hosts event - fetching all hosts from database');
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const allHosts = await invoke<Host[]>('get_all_hosts');
      if (allHosts) {
        set(state => {
          // Create a map of existing hosts by IP for quick lookup
          const existingHostsMap = new Map(state.hosts.map(h => [h.ip, h]));
          
          // Merge DB hosts with existing live data
          const mergedHosts = allHosts.map(dbHost => {
            const existing = existingHostsMap.get(dbHost.ip);
            
            if (!existing) {
              // New host from DB, use as-is
              return dbHost;
            }
            
            // Check if critical host data has changed
            const hasChanges = hasHostDataChanged(existing, dbHost);
            const countsChanged = existing.port_count !== dbHost.port_count || 
                                 existing.vulnerability_count !== dbHost.vulnerability_count;
            
            // If no changes detected, preserve existing host
            if (!hasChanges && !countsChanged && 
                existing.last_seen === dbHost.last_seen &&
                existing.updated_at === dbHost.updated_at) {
              return existing;
            }
            
            // Merge: preserve existing hostname/vendor/OS when DB has null/undefined/empty
            // Prefer DB values when they exist and are non-empty
            return {
              ...existing,
              ...dbHost,
              // Preserve hostname/vendor/OS if DB values are null/undefined/empty
              hostname: dbHost.hostname || existing.hostname,
              vendor: dbHost.vendor || existing.vendor,
              os_name: dbHost.os_name || existing.os_name,
              os_family: dbHost.os_family || existing.os_family,
              os_accuracy: dbHost.os_accuracy ?? existing.os_accuracy,
              mac_address: dbHost.mac_address || existing.mac_address,
              // For status, prefer 'up' from live events over DB
              status: existing.status === 'up' ? existing.status : dbHost.status,
              // Always update these from DB (they should be most current)
              port_count: dbHost.port_count,
              vulnerability_count: dbHost.vulnerability_count,
              last_seen: dbHost.last_seen,
              updated_at: dbHost.updated_at,
              // Preserve notes and tags if DB has empty/null
              notes: dbHost.notes ?? existing.notes,
              tags: dbHost.tags && dbHost.tags.length > 0 ? dbHost.tags : existing.tags,
              scan_progress: dbHost.scan_progress ?? existing.scan_progress,
            };
          });
          
          // Add any existing hosts that aren't in DB (shouldn't happen, but preserve them)
          const dbHostsIps = new Set(allHosts.map(h => h.ip));
          const missingHosts = state.hosts.filter(h => !dbHostsIps.has(h.ip));
          
          console.log(`[hostStore] Periodic refresh: merged ${allHosts.length} hosts from DB, preserved ${missingHosts.length} existing hosts`);
          return { hosts: [...mergedHosts, ...missingHosts] };
        });
      }
    } catch (error) {
      console.error('[hostStore] Failed to refresh all hosts:', error);
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
