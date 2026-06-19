// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { listen } from '@tauri-apps/api/event';
import { Eye, EyeOff, Network, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react';
import React, { useEffect, useRef, useState } from 'react';
import type { Host } from '../stores/hostStore';

interface NetworkMapProps {
  hosts: Host[];
  onHostSelect: (host: Host) => void;
  selectedHostIp?: string;
  className?: string;
}

type HostRole = 'gateway' | 'server' | 'client' | 'unknown' | 'cluster';

interface NetworkNode {
  id: string;
  x: number;
  y: number;
  host?: Host;
  clusterHosts?: Host[];
  isCluster: boolean;
  clusterLabel?: string;
  subnet: string;
  role: HostRole;
}

const CLUSTER_THRESHOLD = 20;

const NetworkMap: React.FC<NetworkMapProps> = ({ hosts, onHostSelect, selectedHostIp }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<NetworkNode[]>([]);
  const [liveHosts, setLiveHosts] = useState<Host[]>(hosts);
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [showLabels, setShowLabels] = useState(true);
  const [showServices, setShowServices] = useState(false);
  const [showLegend, setShowLegend] = useState(true);
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set());

  useEffect(() => {
    setLiveHosts(hosts);
  }, [hosts]);

  useEffect(() => {
    let unlistenHost: (() => void) | undefined;
    let unlistenService: (() => void) | undefined;

    listen<Host>('obs:host', (event) => {
      const host = event.payload;
      setLiveHosts((prev) => {
        if (prev.find((h) => h.ip === host.ip)) return prev;
        return [...prev, host];
      });
    }).then((f) => (unlistenHost = f));

    listen<any>('obs:service', (event) => {
      const svc = event.payload as { ip: string };
      setLiveHosts((prev) =>
        prev.map((h) =>
          h.ip === svc.ip
            ? { ...h, port_count: (h.port_count || 0) + 1 }
            : h
        )
      );
    }).then((f) => (unlistenService = f));

    return () => {
      if (unlistenHost) unlistenHost();
      if (unlistenService) unlistenService();
    };
  }, []);

  const getHostRole = (host: Host): HostRole => {
    const ip = host.ip;
    const portCount = host.port_count || 0;

    if (ip.endsWith('.1') || ip.endsWith('.254')) return 'gateway';
    if (portCount > 10) return 'server';
    if (portCount <= 3) return 'client';
    return 'unknown';
  };

  const groupBySubnet = (hostList: Host[]) => {
    const subnets = new Map<string, Host[]>();
    hostList.forEach((host) => {
      const subnet = host.ip.split('.').slice(0, 3).join('.');
      if (!subnets.has(subnet)) {
        subnets.set(subnet, []);
      }
      subnets.get(subnet)!.push(host);
    });
    return subnets;
  };

  const placeOnRing = (
    items: { id: string; host?: Host; clusterHosts?: Host[]; isCluster: boolean; clusterLabel?: string; role: HostRole }[],
    centerX: number,
    centerY: number,
    radius: number,
    subnet: string,
    startAngle = 0,
    sweep = 2 * Math.PI,
  ): NetworkNode[] => {
    if (items.length === 0) return [];

    return items.map((item, index) => {
      const angle = startAngle + ((index + 0.5) / items.length) * sweep;
      return {
        id: item.id,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        host: item.host,
        clusterHosts: item.clusterHosts,
        isCluster: item.isCluster,
        clusterLabel: item.clusterLabel,
        subnet,
        role: item.role,
      };
    });
  };

  const buildSubnetNodes = (
    subnet: string,
    subnetHosts: Host[],
    centerX: number,
    centerY: number,
    canvasSize: number,
  ): NetworkNode[] => {
    const gateways = subnetHosts.filter((h) => getHostRole(h) === 'gateway');
    const servers = subnetHosts.filter((h) => getHostRole(h) === 'server');
    const clients = subnetHosts.filter((h) => getHostRole(h) === 'client');
    const unknowns = subnetHosts.filter((h) => getHostRole(h) === 'unknown');

    const clientClusterId = `${subnet}-client`;
    const unknownClusterId = `${subnet}-unknown`;
    const shouldClusterClients = clients.length > CLUSTER_THRESHOLD && !expandedClusters.has(clientClusterId);
    const shouldClusterUnknowns = unknowns.length > CLUSTER_THRESHOLD && !expandedClusters.has(unknownClusterId);

    const prominent: {
      id: string;
      host?: Host;
      clusterHosts?: Host[];
      isCluster: boolean;
      clusterLabel?: string;
      role: HostRole;
    }[] = [
      ...gateways.map((h) => ({ id: h.ip, host: h, isCluster: false, role: 'gateway' as HostRole })),
      ...servers.map((h) => ({ id: h.ip, host: h, isCluster: false, role: 'server' as HostRole })),
    ];

    if (shouldClusterClients) {
      prominent.push({
        id: clientClusterId,
        isCluster: true,
        clusterHosts: clients,
        clusterLabel: `${clients.length} client hosts`,
        role: 'cluster',
      });
    } else {
      prominent.push(
        ...clients.map((h) => ({ id: h.ip, host: h, isCluster: false, role: 'client' as HostRole })),
      );
    }

    if (shouldClusterUnknowns) {
      prominent.push({
        id: unknownClusterId,
        isCluster: true,
        clusterHosts: unknowns,
        clusterLabel: `${unknowns.length} unknown hosts`,
        role: 'cluster',
      });
    } else {
      prominent.push(
        ...unknowns.map((h) => ({ id: h.ip, host: h, isCluster: false, role: 'unknown' as HostRole })),
      );
    }

    const hub = gateways[0];
    const hubX = hub ? centerX : centerX;
    const hubY = hub ? centerY : centerY;
    const baseRadius = Math.min(canvasSize * 0.35, 40 + prominent.length * 4);
    const outerRadius = Math.max(baseRadius, 60);

    const nodes: NetworkNode[] = [];

    if (hub) {
      nodes.push({
        id: hub.ip,
        x: hubX,
        y: hubY,
        host: hub,
        isCluster: false,
        subnet,
        role: 'gateway',
      });
    }

    const ringItems = prominent.filter((item) => item.id !== hub?.ip);
    nodes.push(...placeOnRing(ringItems, hubX, hubY, outerRadius, subnet));

    return nodes;
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
  }, []);

  useEffect(() => {
    if (liveHosts.length === 0) {
      setNodes([]);
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const canvasSize = Math.min(rect.width, rect.height);
    const subnets = groupBySubnet(liveHosts);
    const subnetEntries = Array.from(subnets.entries());

    let newNodes: NetworkNode[] = [];

    if (subnetEntries.length === 1) {
      const [subnet, subnetHosts] = subnetEntries[0];
      newNodes = buildSubnetNodes(subnet, subnetHosts, centerX, centerY, canvasSize);
    } else {
      const subnetRadius = canvasSize * 0.28;
      subnetEntries.forEach(([subnet, subnetHosts], subnetIndex) => {
        const subnetAngle = (subnetIndex / subnetEntries.length) * 2 * Math.PI;
        const subnetCenterX = centerX + Math.cos(subnetAngle) * subnetRadius;
        const subnetCenterY = centerY + Math.sin(subnetAngle) * subnetRadius;
        const hostRadius = Math.max(50, Math.min(120, 30 + subnetHosts.length * 2));
        newNodes.push(
          ...buildSubnetNodes(subnet, subnetHosts, subnetCenterX, subnetCenterY, hostRadius * 2),
        );
      });
    }

    setNodes(newNodes);
  }, [liveHosts, expandedClusters]);

  const getNodeColor = (node: NetworkNode) => {
    if (node.isCluster) return '#64748b';

    const host = node.host!;
    if (host.status === 'down') return '#6b7280';

    const vulnCount = host.vulnerability_count || 0;
    if (vulnCount === 0) {
      switch (node.role) {
        case 'gateway': return '#8b5cf6';
        case 'server': return '#3b82f6';
        case 'client': return '#16a34a';
        default: return '#6b7280';
      }
    }
    if (vulnCount < 5) return '#eab308';
    if (vulnCount < 10) return '#ea580c';
    return '#dc2626';
  };

  const drawNodeShape = (ctx: CanvasRenderingContext2D, node: NetworkNode, isSelected: boolean) => {
    const size = node.isCluster ? (isSelected ? 18 : 14) : (isSelected ? 12 : 8);
    const color = getNodeColor(node);

    ctx.fillStyle = color;

    if (node.isCluster) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
      ctx.fill();
      ctx.strokeStyle = '#94a3b8';
      ctx.lineWidth = 2;
      ctx.stroke();
      return;
    }

    switch (node.role) {
      case 'gateway':
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - size);
        ctx.lineTo(node.x + size, node.y);
        ctx.lineTo(node.x, node.y + size);
        ctx.lineTo(node.x - size, node.y);
        ctx.closePath();
        ctx.fill();
        break;
      case 'server':
        ctx.fillRect(node.x - size / 2, node.y - size / 2, size, size);
        break;
      case 'client':
        ctx.beginPath();
        ctx.arc(node.x, node.y, size / 2, 0, 2 * Math.PI);
        ctx.fill();
        break;
      default:
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - size);
        ctx.lineTo(node.x - size, node.y + size);
        ctx.lineTo(node.x + size, node.y + size);
        ctx.closePath();
        ctx.fill();
    }

    if (isSelected) {
      ctx.strokeStyle = '#3b82f6';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
  };

  const findHub = (subnetNodes: NetworkNode[]): NetworkNode | null => {
    const gateway = subnetNodes.find((n) => n.role === 'gateway' && !n.isCluster);
    if (gateway) return gateway;

    if (subnetNodes.length === 0) return null;

    const avgX = subnetNodes.reduce((sum, n) => sum + n.x, 0) / subnetNodes.length;
    const avgY = subnetNodes.reduce((sum, n) => sum + n.y, 0) / subnetNodes.length;
    return {
      ...subnetNodes[0],
      x: avgX,
      y: avgY,
      id: `${subnetNodes[0].subnet}-hub`,
      isCluster: false,
      role: 'gateway',
    };
  };

  const drawNetwork = () => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.save();
    ctx.translate(offset.x, offset.y);
    ctx.scale(scale, scale);

    const subnets = new Map<string, NetworkNode[]>();
    nodes.forEach((node) => {
      if (!subnets.has(node.subnet)) subnets.set(node.subnet, []);
      subnets.get(node.subnet)!.push(node);
    });

    subnets.forEach((subnetNodes) => {
      const hub = findHub(subnetNodes);
      if (!hub) return;

      ctx.strokeStyle = '#374151';
      ctx.lineWidth = 1;
      ctx.globalAlpha = 0.35;

      subnetNodes.forEach((node) => {
        if (node.id === hub.id) return;
        ctx.beginPath();
        ctx.moveTo(hub.x, hub.y);
        ctx.lineTo(node.x, node.y);
        ctx.stroke();
      });
    });

    const gateways = nodes.filter((n) => n.role === 'gateway' && !n.isCluster);
    if (gateways.length > 1) {
      ctx.strokeStyle = '#8b5cf6';
      ctx.lineWidth = 2;
      ctx.globalAlpha = 0.3;
      for (let i = 0; i < gateways.length; i++) {
        for (let j = i + 1; j < gateways.length; j++) {
          if (gateways[i].subnet !== gateways[j].subnet) {
            ctx.beginPath();
            ctx.moveTo(gateways[i].x, gateways[i].y);
            ctx.lineTo(gateways[j].x, gateways[j].y);
            ctx.stroke();
          }
        }
      }
    }

    ctx.globalAlpha = 1;

    nodes.forEach((node) => {
      const isSelected = node.isCluster
        ? false
        : node.host?.ip === selectedHostIp;
      drawNodeShape(ctx, node, isSelected);

      if (showLabels && scale > 0.4) {
        ctx.fillStyle = '#f9fafb';
        ctx.font = node.isCluster ? '11px monospace' : '10px monospace';
        ctx.textAlign = 'center';

        const label = node.isCluster
          ? node.clusterLabel || 'Cluster'
          : (node.host?.hostname || node.host?.ip || '');
        const shortLabel = label.length > 18 ? `${label.substring(0, 15)}...` : label;
        ctx.fillText(shortLabel, node.x, node.y - (node.isCluster ? 20 : 15));

        if (!node.isCluster && showServices && (node.host?.port_count || 0) > 0) {
          ctx.font = '8px monospace';
          ctx.fillStyle = '#9ca3af';
          ctx.fillText(`${node.host?.port_count || 0} ports`, node.x, node.y + 20);
        }

        if (node.isCluster) {
          ctx.font = '8px monospace';
          ctx.fillStyle = '#94a3b8';
          ctx.fillText('click to expand', node.x, node.y + 22);
        }
      }
    });

    ctx.restore();
  };

  const handleNodeClick = (node: NetworkNode) => {
    if (node.isCluster) {
      setExpandedClusters((prev) => new Set([...prev, node.id]));
      return;
    }
    if (node.host) {
      onHostSelect(node.host);
    }
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;

    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const clickedNode = getNodeAt(x, y);

    if (clickedNode) {
      handleNodeClick(clickedNode);
      return;
    }

    setIsDragging(true);
    setDragStart({ x: e.clientX - offset.x, y: e.clientY - offset.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setOffset({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => setIsDragging(false);

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setScale((prev) => Math.max(0.1, Math.min(3, prev * delta)));
  };

  const getNodeAt = (x: number, y: number): NetworkNode | null => {
    const transformedX = (x - offset.x) / scale;
    const transformedY = (y - offset.y) / scale;

    return nodes.find((node) => {
      const hitRadius = node.isCluster ? 16 : 12;
      const distance = Math.sqrt(
        (transformedX - node.x) ** 2 + (transformedY - node.y) ** 2,
      );
      return distance <= hitRadius;
    }) || null;
  };

  const resetView = () => {
    setScale(1);
    setOffset({ x: 0, y: 0 });
    setExpandedClusters(new Set());
  };

  const zoomIn = () => setScale((prev) => Math.min(3, prev * 1.2));
  const zoomOut = () => setScale((prev) => Math.max(0.1, prev / 1.2));

  useEffect(() => {
    drawNetwork();
  }, [nodes, scale, offset, selectedHostIp, showLabels, showServices]);

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 flex flex-col h-full">
      <div className="p-2 border-b border-gray-700">
        <div className="flex items-center justify-start">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowLabels(!showLabels)}
              className={`p-2 rounded transition-colors ${showLabels ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
              title="Toggle Labels"
            >
              {showLabels ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
            </button>

            <button
              onClick={() => setShowServices(!showServices)}
              className={`p-2 rounded transition-colors text-xs px-3 ${showServices ? 'bg-green-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
              title="Toggle Service Info"
            >
              SVC
            </button>

            <div className="flex bg-gray-800 rounded">
              <button onClick={zoomOut} className="p-2 hover:bg-gray-600 rounded-l transition-colors" title="Zoom Out">
                <ZoomOut className="w-4 h-4 text-gray-300" />
              </button>
              <button onClick={resetView} className="p-2 hover:bg-gray-600 transition-colors" title="Reset View">
                <RotateCcw className="w-4 h-4 text-gray-300" />
              </button>
              <button onClick={zoomIn} className="p-2 hover:bg-gray-600 rounded-r transition-colors" title="Zoom In">
                <ZoomIn className="w-4 h-4 text-gray-300" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="relative flex-1">
        <canvas
          ref={canvasRef}
          className="w-full h-full cursor-grab active:cursor-grabbing"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onWheel={handleWheel}
        />

        {liveHosts.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-gray-400">
            <div className="text-center">
              <Network className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>No hosts to display</p>
              <p className="text-sm">Start a scan to discover network topology</p>
            </div>
          </div>
        )}

        <div className="absolute top-4 left-4">
          <button
            onClick={() => setShowLegend(!showLegend)}
            className="bg-gray-800/90 p-2 rounded border border-gray-600 hover:bg-gray-700/90 transition-colors"
            title="Toggle Legend"
          >
            <Network className="w-4 h-4 text-gray-300" />
          </button>

          {showLegend && (
            <div className="mt-2 bg-gray-800/90 p-3 rounded border border-gray-600 min-w-[140px]">
              <div className="text-xs text-gray-300 mb-2 font-medium">Host Types</div>
              <div className="space-y-1 text-xs mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-purple-500 transform rotate-45" />
                  <span className="text-gray-300">Gateway</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-blue-500" />
                  <span className="text-gray-300">Server</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="text-gray-300">Client</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-slate-500 border border-slate-400" />
                  <span className="text-gray-300">Cluster (click)</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkMap;
