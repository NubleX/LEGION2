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
  unsubs.push(await listen('obs:metric', (e) => onMetric(e.payload)));
  return () => unsubs.forEach((u) => u());
}

