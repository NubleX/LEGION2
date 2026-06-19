// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, originally created by Gotham Security.
// Archived in 2024.

export interface ScanConfig {
  targets: string;
  scanType: string;
  ports?: string;
  excludeHosts?: string;
  useNmap?: boolean;
  useMasscan?: boolean;
  extra?: string;
  rate?: number;
  detectOS?: boolean;
  detectVersions?: boolean;
  skipPing?: boolean;
  interface?: string;
}

// Plan types from backend
export interface Plan {
  scan_id: string;
  targets: string;
  ports: string;
  rate?: number;
  extra: string[];
  modules: string[];
  source_type: string;
  sink_types: string[];
  interface?: string;
  nse_scripts?: string[];
  nse_script_args?: Record<string, string>;
}

export type ScanType =
  | 'Discovery'
  | 'PortScan'
  | 'ServiceDetection'
  | 'Vulnerability'
  | 'Comprehensive'
  | 'Quick'
  | 'Stealth'
  | { Custom: { options: string } };

export type ScanTiming =
  | 'Paranoid'
  | 'Sneaky'
  | 'Polite'
  | 'Normal'
  | 'Aggressive'
  | 'Insane';

export interface PortRange {
  start: number;
  end: number;
  top_ports?: number;
}

export type Protocol = 'Tcp' | 'Udp';

export type PortState = 'Open' | 'Closed' | 'Filtered' | 'Unknown';

// Coordinator API types
export interface ScanOptions {
  ports?: string;
  rate?: number;
  extra_args?: string[];
  use_masscan?: boolean;
}

export interface ScanRequest {
  target: string;
  scan_type: ScanType;
  options?: ScanOptions;
}

export interface ScannerStatus {
  nmap_available: boolean;
  masscan_available: boolean;
  ready: boolean;
}
