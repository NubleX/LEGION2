// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

/**
 * Execute a scan via the backend ScanCoordinator.
 * Returns the created scan ID.
 */
async function startScan(targets: string, ports: string, rate = 5000) {
  const request = {
    target: targets,
    scanType: 'PortScan',
    options: {
      ports,
      rate,
      extraArgs: [] as string[],
    },
  };
  const scanId = await invoke<string>('start_scan', { request });
  return scanId;
}

/**
 * Get the current progress for an active scan.
 */
async function getScanProgress(scanId: string) {
  const result = await invoke<string>('get_scan_progress', { scanId });
  return JSON.parse(result);
}

/**
 * Retrieve aggregated scan statistics from the backend.
 */
async function getScanStatistics() {
  const result = await invoke<string>('get_scan_statistics');
  return JSON.parse(result);
}

/**
 * Check if any network scans are currently running.
 */
async function isScanning() {
  const active = await invoke<string[]>('get_active_scans');
  return active.length > 0;
}

/**
 * Cancel an active network scan.
 */
async function cancelNetworkScan(scanId: string) {
  await invoke('cancel_scan', { scanId });
}

/**
 * Subscribe to observation events emitted by the backend.
 * Returns a function to unsubscribe all listeners.
 */
async function subscribeObs(
  onHost: (o: any) => void,
  onService: (o: any) => void,
  onLog: (o: any) => void,
): Promise<() => void> {
  const unsubs: Array<() => void> = [];
  unsubs.push(await listen('obs:service', (e) => onService(e.payload)));
  unsubs.push(await listen('obs:host', (e) => onHost(e.payload)));
  unsubs.push(await listen('obs:metrics', (e) => onLog(e.payload)));
  return () => unsubs.forEach((u) => u());
}

export const scanAPI = {
  startScan,
  getScanProgress,
  getScanStatistics,
  isScanning,
  cancelNetworkScan,
  subscribeObs,
};
