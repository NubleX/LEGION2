// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { create } from 'zustand';

export interface Vulnerability {
  id: string;
  host_ip: string;
  port: number;
  service: string;
  name: string;
  severity: string;
  description: string;
  cvss_score?: number;
  timestamp: string;
  cve_id?: string;
  remediation?: string;
  references?: string[];
}

interface VulnStore {
  vulnsByHost: Record<string, Vulnerability[]>;
  addVulnerability: (vuln: Vulnerability) => void;
  getHostVulnerabilities: (ip: string) => Vulnerability[];
  setHostVulnerabilities: (ip: string, vulns: Vulnerability[]) => void;
  clear: () => void;
}

const useVulnStore = create<VulnStore>((set, get) => ({
  vulnsByHost: {},
  addVulnerability: (vuln) =>
    set((state) => ({
      vulnsByHost: {
        ...state.vulnsByHost,
        [vuln.host_ip]: [...(state.vulnsByHost[vuln.host_ip] || []), vuln],
      },
    })),
  getHostVulnerabilities: (ip) => get().vulnsByHost[ip] || [],
  setHostVulnerabilities: (ip, vulns) =>
    set((state) => ({
      vulnsByHost: { ...state.vulnsByHost, [ip]: vulns },
    })),
  clear: () => set({ vulnsByHost: {} }),
}));

export default useVulnStore;
