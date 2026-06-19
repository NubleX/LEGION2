// LEGION2 - Scan phase labeling utilities
// Copyright (c) 2025 NubleX / Igor Dunaev

import type { Plan } from '../types/scanning';

export function getPhaseLabel(plan: Plan, index: number, total: number): string {
  const phaseNumber = index + 1;
  const phaseSuffix = `Phase ${phaseNumber}/${total}`;

  if (plan.source_type === 'masscan') {
    return `Port Scan (${phaseSuffix})`;
  }

  if (plan.source_type === 'nmap') {
    return index === total - 1
      ? `Service Detection (${phaseSuffix})`
      : `Host Discovery (${phaseSuffix})`;
  }

  return `${plan.source_type} (${phaseSuffix})`;
}
