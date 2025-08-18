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

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { ScanConfig, Plan } from '../types/scanning';

/**
 * Execute a scan plan by delegating to the backend engine.
 */
export async function engineExecute(plan: any): Promise<void> {
  await invoke('engine_execute', { plan });
}

/**
 * Subscribe to observation events emitted by the backend.
 * Returns an unsubscribe function to remove all listeners.
 */
export async function subscribeObs(
  onHost: (data: any) => void,
  onService: (data: any) => void,
  onMetric: (data: any) => void
): Promise<() => void> {
  const unsubs: Array<() => void> = [];
  unsubs.push(await listen('obs:service', (e) => onService(e.payload)));
  unsubs.push(await listen('obs:host', (e) => onHost(e.payload)));
  unsubs.push(await listen('obs:metrics', (e) => onMetric(e.payload)));
  return () => unsubs.forEach((u) => u());
}

//  Update Frontend to Pass Scan Types

export async function startScan(config: ScanConfig): Promise<string> {
  // Build extra arguments based on scan type
  const extraArgs = buildExtraArgs(config);

  const plan: Plan = {
    scan_id: crypto.randomUUID(),
    targets: config.targets,
    ports: config.ports || '1-1000',
    rate: config.rate,
    extra: extraArgs,
    modules: [],
    source_type: config.useMasscan ? 'masscan' : 'nmap',
    sink_types: ['ui', 'db', 'vulnerability']
  };

  await invoke('engine_execute', { plan });
  return plan.scan_id;
}

function buildExtraArgs(config: ScanConfig): string[] {
  const args: string[] = [];

  if (config.useNmap) {
    switch (config.scanType) {
      case 'quick':
        args.push('-T4', '-F');
        break;
      case 'comprehensive':
        args.push('-sS', '-sV', '-O', '-A', '-T4');
        break;
      case 'stealth':
        args.push('-sS', '-T2', '-f', '--randomize-hosts');
        break;
      case 'discovery':
        args.push('-sn', '-T4');
        break;
      default:
        args.push('-sS', '-T3'); // Default scan
    }

    if (config.detectOS) args.push('-O');
    if (config.detectVersions) args.push('-sV');
    if (config.skipPing) args.push('-Pn');
  }

  // Add user's custom extra arguments
  if (config.extra) {
    const customArgs = config.extra.split(' ').filter(a => a.trim());
    args.push(...customArgs);
  }

  return args;
}