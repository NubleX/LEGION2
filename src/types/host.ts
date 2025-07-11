import { Host } from '../stores/hostStore'

export interface PortInfo {
  port: number;
  protocol: 'tcp' | 'udp';
  service?: string;
  state: 'open' | 'closed' | 'filtered';
  banner?: string;
}
export interface HostStore {
  hosts: Host[];
  selectedHostId?: string;
  setSelectedHost: (host: Host | null) => void;
  addHost: (host: Host) => void;
  updateHost: (id: string, updates: Partial<Host>) => void;
  removeHost: (id: string) => void;
  clearHosts: () => void;
}
export interface HostSearchParams {
  ip?: string;
  hostname?: string;
  mac?: string;
  os?: string;
  status?: 'up' | 'down';
  port?: number;
}
export interface HostFilter {
  ip?: string;
  hostname?: string;
  mac?: string;
  os?: string;
  status?: 'up' | 'down';
  port?: number;
}
export interface HostSort {
  field: keyof Host;
  direction: 'asc' | 'desc';
}