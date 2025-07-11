import { Host } from '../stores/hostStore'

export interface NetworkTopology {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  subnets: SubnetInfo[];
  layout: LayoutConfig;
}

export interface NetworkNode {
  id: string;
  x: number;
  y: number;
  host: Host;
  connections: string[];
  subnet?: string;
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  type: 'subnet' | 'route' | 'service';
  strength?: number;
}

export interface SubnetInfo {
  id: string;
  cidr: string;
  gateway?: string;
  hostCount: number;
  color: string;
}

export interface LayoutConfig {
  algorithm: 'force' | 'hierarchical' | 'circular';
  spacing: number;
  groupBySubnet: boolean;
}