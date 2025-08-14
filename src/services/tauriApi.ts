// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
// Forked from an earlier version of LEGION, originally created by Gotham Security.
// Archived in 2024.

// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details. You should have received a copy
// of the GNU General Public License along with this program.
// If not, see <http://www.gnu.org/licenses/>.

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

/**
 * Execute a scan plan via the backend engine.
 */
async function startScan(targets: string, ports: string, rate = 5000) {
  const plan = {
    scan_id: crypto.randomUUID(),
    targets,
    ports,
    rate,
    extra: [] as string[],
    modules: [] as string[],
  };
  await invoke('engine_execute', { plan });
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
  unsubs.push(await listen('obs:metric', (e) => onLog(e.payload)));
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
