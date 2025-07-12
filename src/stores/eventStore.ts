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
import { listen } from '@tauri-apps/api/event';
import { ScanEvent, EventType } from '../types/events';

interface EventStore {
  events: ScanEvent[];
  listeners: Map<EventType, ((data: any) => void)[]>;
  isConnected: boolean;
  
  connect: () => Promise<void>;
  addEventListener: (type: EventType, callback: (data: any) => void) => void;
  removeEventListener: (type: EventType, callback: (data: any) => void) => void;
}

export const useEventStore = create<EventStore>((set, get) => ({
  events: [],
  listeners: new Map(),
  isConnected: false,
  
  connect: async () => {
    try {
      await invoke('setup_event_stream');
      
      // Listen for events from backend
      listen('scan-event', (event: any) => {
        const scanEvent = event.payload as ScanEvent;
        
        // Add to events list
        set(state => ({
          events: [...state.events.slice(-999), scanEvent] // Keep last 1000 events
        }));
        
        // Notify listeners
        const listeners = get().listeners.get(scanEvent.event_type);
        if (listeners) {
          listeners.forEach(callback => callback(scanEvent.data));
        }
      });
      
      set({ isConnected: true });
    } catch (error) {
      console.error('Failed to connect to event stream:', error);
    }
  },
  
  addEventListener: (type: EventType, callback: (data: any) => void) => {
    const listeners = get().listeners;
    const typeListeners = listeners.get(type) || [];
    typeListeners.push(callback);
    listeners.set(type, typeListeners);
    set({ listeners });
  },
  
  removeEventListener: (type: EventType, callback: (data: any) => void) => {
    const listeners = get().listeners;
    const typeListeners = listeners.get(type) || [];
    const filtered = typeListeners.filter(cb => cb !== callback);
    listeners.set(type, filtered);
    set({ listeners });
  }
}));