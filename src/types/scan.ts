export type ScanConfig = {
  targets: string;
  scanType: 'quick' | 'comprehensive' | 'stealth' | 'custom';
  ports: string;
  excludeHosts: string;
  useNmap: boolean;
  useMasscan: boolean;
  nmapOptions: string;
  masscanRate: number;
  detectOS: boolean;
  detectVersions: boolean;
  skipPing: boolean;
};