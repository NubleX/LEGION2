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
import { listen } from '@tauri-apps/api/event';

export interface Host {
  ip: string;
  hostname?: string;
  timestamp?: string;
  id?: string;
  status?: string;
  port_count?: number;
  vulnerability_count?: number;
  mac_address?: string;
  vendor?: string;
  os_name?: string;
  os_family?: string;
  os_accuracy?: number;
  last_seen?: string;
  created_at?: string;
  updated_at?: string;
}

interface HostStore {
  hosts: Host[];
  getHosts: () => Host[];
  getHost: (ip: string) => Host | undefined;
}

const useHostStore = create<HostStore>((set, get) => {
  // Listen for host events from the backend and update the store
  listen('obs:host', (event: any) => {
    const host = event.payload as Host;
    set(state => {
      const idx = state.hosts.findIndex(h => h.ip === host.ip);
      if (idx !== -1) {
        const updated = [...state.hosts];
        updated[idx] = host;
        return { hosts: updated };
      }
      return { hosts: [...state.hosts, host] };
    });
  }).catch(console.error);

  return {
    hosts: [],
    getHosts: () => get().hosts,
    getHost: (ip: string) => get().hosts.find(h => h.ip === ip),
  };
});

export default useHostStore;
