// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

export interface ServiceInfo {
  name: string;
  port: number;
  protocol: string;
  state: string;
  version?: string;
  banner?: string;
  cve_count: number;
  enrichment_status: 'none' | 'pending' | 'completed' | 'error';
}

export interface CveInfo {
  id: string;
  name: string;
  severity: string;
  cvss_score?: number;
  description?: string;
}

export interface ServiceEnrichment {
  service: ServiceInfo;
  cves: CveInfo[];
  osint_data?: {
    shodan?: any;
    censys?: any;
    reputation?: number;
    exploit_available?: boolean;
  };
  enriched_at?: string;
  source?: string;
}

