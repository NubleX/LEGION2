// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { listen } from '@tauri-apps/api/event';
import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import type { ServiceInfo, CveInfo } from '../types/services';

interface ServiceStore {
  services: Record<string, ServiceInfo[]>; // host_ip -> services[]
  cves: Record<string, CveInfo[]>; // service key (host_ip:port) -> cves[]
  loading: Record<string, boolean>; // host_ip -> loading state
  getServices: (hostIp: string) => ServiceInfo[];
  getServiceCves: (hostIp: string, port: number) => CveInfo[];
  setServices: (hostIp: string, services: ServiceInfo[]) => void;
  addService: (hostIp: string, service: ServiceInfo) => void;
  setCves: (hostIp: string, port: number, cves: CveInfo[]) => void;
  setLoading: (hostIp: string, loading: boolean) => void;
  loadServices: (hostIp: string) => Promise<void>;
  loadServiceCves: (hostIp: string, port: number, serviceName?: string) => Promise<void>;
}

const useServiceStore = create<ServiceStore>((set, get) => {
  // Listen for service events from the backend
  listen('obs:service', (event: any) => {
    const serviceEvent = event.payload;
    if (serviceEvent?.ip) {
      console.log('Received obs:service event for', serviceEvent.ip);
      // Trigger a refresh of services for this host
      const store = get();
      store.loadServices(serviceEvent.ip).catch(console.error);
    }
  }).catch(console.error);

  return {
    services: {},
    cves: {},
    loading: {},

    getServices: (hostIp: string) => {
      return get().services[hostIp] || [];
    },

    getServiceCves: (hostIp: string, port: number) => {
      const key = `${hostIp}:${port}`;
      return get().cves[key] || [];
    },

    setServices: (hostIp: string, services: ServiceInfo[]) => {
      set((state) => ({
        services: {
          ...state.services,
          [hostIp]: services,
        },
      }));
    },

    addService: (hostIp: string, service: ServiceInfo) => {
      set((state) => {
        const existing = state.services[hostIp] || [];
        const index = existing.findIndex(
          (s) => s.port === service.port && s.protocol === service.protocol
        );
        if (index >= 0) {
          // Update existing service
          const updated = [...existing];
          updated[index] = service;
          return {
            services: {
              ...state.services,
              [hostIp]: updated,
            },
          };
        } else {
          // Add new service
          return {
            services: {
              ...state.services,
              [hostIp]: [...existing, service],
            },
          };
        }
      });
    },

    setCves: (hostIp: string, port: number, cves: CveInfo[]) => {
      const key = `${hostIp}:${port}`;
      set((state) => ({
        cves: {
          ...state.cves,
          [key]: cves,
        },
      }));
    },

    setLoading: (hostIp: string, loading: boolean) => {
      set((state) => ({
        loading: {
          ...state.loading,
          [hostIp]: loading,
        },
      }));
    },

    loadServices: async (hostIp: string) => {
      const store = get();
      store.setLoading(hostIp, true);
      try {
        const services = await invoke<ServiceInfo[]>('get_host_services', {
          hostIp,
        });
        store.setServices(hostIp, services);
      } catch (error) {
        console.error(`Failed to load services for host ${hostIp}:`, error);
        store.setServices(hostIp, []);
      } finally {
        store.setLoading(hostIp, false);
      }
    },

    loadServiceCves: async (hostIp: string, port: number, serviceName?: string) => {
      const store = get();
      try {
        const cves = await invoke<CveInfo[]>('get_service_cves', {
          hostIp,
          port,
          serviceName,
        });
        store.setCves(hostIp, port, cves);
      } catch (error) {
        console.error(`Failed to load CVEs for service ${hostIp}:${port}:`, error);
        store.setCves(hostIp, port, []);
      }
    },
  };
});

export default useServiceStore;

