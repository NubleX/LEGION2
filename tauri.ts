// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { invoke } from '@tauri-apps/api/core';

export async function invokeTauriCommand<T = any>(
  _cmd: string,
  _args?: Record<string, any>
): Promise<T> {
  throw new Error('Unable to access Tauri API. Make sure the app is running in Tauri context.');
}

export function callTauriCommand(cmd: string, args = {}) {
  return invoke(cmd, args);
}


export { listen } from '@tauri-apps/api/event';
