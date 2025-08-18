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
//
// Dedicated store for vulnerability events keyed by host IP
// Stores vulnerabilities received from backend events so components can
// access them without relying on in-memory merges.

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
