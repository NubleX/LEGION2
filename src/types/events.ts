// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

export interface ScanEvent {
  scan_id: string;
  event_type: EventType;
  timestamp: string;
  data: any;
}

export type EventType =
  | 'ScanStarted'
  | 'HostDiscovered'
  | 'PortFound'
  | 'ServiceIdentified'
  | 'VulnerabilityFound'
  | 'ScanProgress'
  | 'ScanCompleted'
  | 'ScanError';

export interface EventListener {
  event_type: EventType;
  callback: (data: any) => void;
}