// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { listen } from '@tauri-apps/api/event';
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type Simulation,
} from 'd3-force';
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

// A node in the force simulation. d3-force adds/mutates x, y, vx, vy, fx, fy
// on these objects in place every tick — this is why node identity must be
// preserved across updates (see syncSimulation): replacing the object loses
// its velocity/position and causes a visible snap instead of a smooth
// transition to the new layout.
interface SimNode {
  id: string;
  x: number;
  y: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
  host?: Host;
  clusterHosts?: Host[];
  isCluster: boolean;
  isSynthetic?: boolean; // hub/anchor nodes that organize the layout but aren't drawn
  clusterLabel?: string;
  subnet: string;
  role: HostRole;
}

interface SimLink {
  source: string | SimNode;
  target: string | SimNode;
  kind: 'member' | 'anchor';
}

const CLUSTER_THRESHOLD = 20;
const CENTER_ANCHOR_ID = '__center__';

const NetworkMap: React.FC<NetworkMapProps> = ({ hosts, onHostSelect, selectedHostIp, className }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [liveHosts, setLiveHosts] = useState<Host[]>(hosts);
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [showLabels, setShowLabels] = useState(true);
  const [showServices, setShowServices] = useState(false);
  const [showLegend, setShowLegend] = useState(true);
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set());
  const [hostCount, setHostCount] = useState(0);

  // Simulation state lives in refs, not React state: positions are mutated
  // 60x/sec by d3-force and drawn straight to canvas on every tick. Routing
  // that through setState/React would re-render the whole component tree
  // every frame — the same class of bug as the obs:progress IPC flood, just
  // on the frontend's own render loop instead of Tauri's.
  const simulationRef = useRef<Simulation<SimNode, SimLink> | null>(null);
  const nodeMapRef = useRef<Map<string, SimNode>>(new Map());
  const linksRef = useRef<SimLink[]>([]);
  const draggedNodeRef = useRef<SimNode | null>(null);
  const mouseDownPosRef = useRef({ x: 0, y: 0 });
  const scaleRef = useRef(scale);
  const offsetRef = useRef(offset);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    scaleRef.current = scale;
  }, [scale]);
  useEffect(() => {
    offsetRef.current = offset;
  }, [offset]);

  useEffect(() => {
    setLiveHosts(hosts);
  }, [hosts]);

  useEffect(() => {
    let unlistenHost: (() => void) | undefined;
    let unlistenService: (() => void) | undefined;

    listen<Host>('obs:host', (event) => {
      const host = event.payload;
      setLiveHosts((prev) => {
        const idx = prev.findIndex((h) => h.ip === host.ip);
        if (idx === -1) return [...prev, host];
        // Merge updated fields (status, port_count, vuln counts) into the
        // existing host instead of dropping the event — otherwise a host
        // discovered early never reflects later port/service/vuln changes
        // on the map.
        const next = prev.slice();
        next[idx] = { ...next[idx], ...host };
        return next;
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

  // Describes the desired node set for the current hosts/cluster state,
  // with no position information — the simulation decides where everything
  // lands, and settles incrementally instead of recomputing angles for
  // every node whenever a single host streams in (that recompute-from-index
  // behavior was the source of the jitter: one new host could shift every
  // other node's angle on a ring).
  interface DesiredEntry {
    id: string;
    host?: Host;
    clusterHosts?: Host[];
    isCluster: boolean;
    clusterLabel?: string;
    subnet: string;
    role: HostRole;
    hubId: string;
  }

  const buildDesiredEntries = (hostList: Host[], expanded: Set<string>): DesiredEntry[] => {
    const subnets = groupBySubnet(hostList);
    const entries: DesiredEntry[] = [];

    subnets.forEach((subnetHosts, subnet) => {
      const gateways = subnetHosts.filter((h) => getHostRole(h) === 'gateway');
      const servers = subnetHosts.filter((h) => getHostRole(h) === 'server');
      const clients = subnetHosts.filter((h) => getHostRole(h) === 'client');
      const unknowns = subnetHosts.filter((h) => getHostRole(h) === 'unknown');

      const hub = gateways[0];
      const hubId = hub ? hub.ip : `${subnet}::hub`;

      if (hub) {
        entries.push({ id: hub.ip, host: hub, isCluster: false, subnet, role: 'gateway', hubId });
      } else {
        // Synthetic, undrawn anchor so the subnet still has a stable point
        // to link members to and to repel other subnets from.
        entries.push({ id: hubId, isCluster: false, subnet, role: 'gateway', hubId });
      }

      gateways.slice(1).forEach((h) =>
        entries.push({ id: h.ip, host: h, isCluster: false, subnet, role: 'gateway', hubId })
      );
      servers.forEach((h) =>
        entries.push({ id: h.ip, host: h, isCluster: false, subnet, role: 'server', hubId })
      );

      const clientClusterId = `${subnet}-client`;
      if (clients.length > CLUSTER_THRESHOLD && !expanded.has(clientClusterId)) {
        entries.push({
          id: clientClusterId,
          isCluster: true,
          clusterHosts: clients,
          clusterLabel: `${clients.length} client hosts`,
          subnet,
          role: 'cluster',
          hubId,
        });
      } else {
        clients.forEach((h) =>
          entries.push({ id: h.ip, host: h, isCluster: false, subnet, role: 'client', hubId })
        );
      }

      const unknownClusterId = `${subnet}-unknown`;
      if (unknowns.length > CLUSTER_THRESHOLD && !expanded.has(unknownClusterId)) {
        entries.push({
          id: unknownClusterId,
          isCluster: true,
          clusterHosts: unknowns,
          clusterLabel: `${unknowns.length} unknown hosts`,
          subnet,
          role: 'cluster',
          hubId,
        });
      } else {
        unknowns.forEach((h) =>
          entries.push({ id: h.ip, host: h, isCluster: false, subnet, role: 'unknown', hubId })
        );
      }
    });

    return entries;
  };

  // Create the simulation once; subsequent updates mutate its node/link
  // sets in place rather than recreating it, which is what makes additions
  // settle smoothly instead of restarting the whole layout.
  useEffect(() => {
    const sim = forceSimulation<SimNode>([])
      .force('charge', forceManyBody().strength(-220))
      .force('collision', forceCollide<SimNode>().radius((d) => (d.isCluster ? 20 : 14)))
      .alphaDecay(0.04)
      .velocityDecay(0.35)
      .on('tick', scheduleDraw);
    simulationRef.current = sim;

    return () => {
      sim.stop();
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Size the canvas to its container and keep it sized. The old version ran
  // this once on mount; because the Topology tab is hidden at mount, the rect
  // was 0x0 and the canvas stayed 0x0 forever (nothing ever drew). A
  // ResizeObserver re-applies sizing whenever the element gains or changes
  // size — including the first time the tab becomes visible — which heals the
  // 0x0 case and handles window resizes.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const applySize = () => {
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      const ctx = canvas.getContext('2d');
      // setTransform (not scale) so repeated resizes don't compound the dpr.
      ctx?.setTransform(dpr, 0, 0, dpr, 0, 0);
      canvas.style.width = rect.width + 'px';
      canvas.style.height = rect.height + 'px';

      const sim = simulationRef.current;
      if (sim) {
        sim.force('center', forceCenter(rect.width / 2, rect.height / 2));
        const center = nodeMapRef.current.get(CENTER_ANCHOR_ID);
        if (center) {
          center.fx = rect.width / 2;
          center.fy = rect.height / 2;
        }
        sim.alpha(Math.max(sim.alpha(), 0.2)).restart();
      }
      scheduleDraw();
    };

    applySize();
    const ro = new ResizeObserver(applySize);
    ro.observe(canvas);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Structural sync: add/remove/relabel nodes without disturbing the
  // position of anything that already existed.
  useEffect(() => {
    const sim = simulationRef.current;
    const canvas = canvasRef.current;
    if (!sim || !canvas) return;

    const rect = canvas.getBoundingClientRect();
    const centerX = rect.width / 2 || 300;
    const centerY = rect.height / 2 || 200;
    const map = nodeMapRef.current;
    const wasEmpty = map.size === 0;

    if (!map.has(CENTER_ANCHOR_ID)) {
      map.set(CENTER_ANCHOR_ID, {
        id: CENTER_ANCHOR_ID,
        x: centerX,
        y: centerY,
        fx: centerX,
        fy: centerY,
        isCluster: false,
        isSynthetic: true,
        subnet: '',
        role: 'unknown',
      });
    }

    const desired = buildDesiredEntries(liveHosts, expandedClusters);
    const desiredIds = new Set(desired.map((e) => e.id));
    desiredIds.add(CENTER_ANCHOR_ID);

    // Drop anything no longer wanted (host went down, cluster expanded, etc).
    for (const id of Array.from(map.keys())) {
      if (!desiredIds.has(id)) map.delete(id);
    }

    desired.forEach((entry) => {
      const existing = map.get(entry.id);
      if (existing) {
        // Update metadata only — x/y/vx/vy keep flowing from the simulation.
        existing.host = entry.host;
        existing.clusterHosts = entry.clusterHosts;
        existing.clusterLabel = entry.clusterLabel;
        existing.subnet = entry.subnet;
        existing.role = entry.role;
        existing.isCluster = entry.isCluster;
        return;
      }

      // Spawn new nodes near their hub (or center, if the hub is also new)
      // instead of at a fixed point, so a burst of new hosts doesn't all
      // launch from the same spot and fly outward together.
      const hub = map.get(entry.hubId);
      const spawnX = (hub?.x ?? centerX) + (Math.random() - 0.5) * 40;
      const spawnY = (hub?.y ?? centerY) + (Math.random() - 0.5) * 40;
      map.set(entry.id, {
        id: entry.id,
        x: spawnX,
        y: spawnY,
        host: entry.host,
        clusterHosts: entry.clusterHosts,
        clusterLabel: entry.clusterLabel,
        isCluster: entry.isCluster,
        subnet: entry.subnet,
        role: entry.role,
      });
    });

    const links: SimLink[] = [];
    const subnetHubIds = new Set<string>();
    desired.forEach((entry) => {
      subnetHubIds.add(entry.hubId);
      if (entry.id !== entry.hubId) {
        links.push({ source: entry.id, target: entry.hubId, kind: 'member' });
      }
    });
    // Weakly tether every subnet's hub to the shared center anchor so
    // multiple subnets spread out around it instead of drifting off-canvas,
    // without forcing them into the old fixed ring positions.
    subnetHubIds.forEach((hubId) => {
      links.push({ source: hubId, target: CENTER_ANCHOR_ID, kind: 'anchor' });
    });
    linksRef.current = links;

    const nodesArray = Array.from(map.values());
    sim.nodes(nodesArray);
    sim.force(
      'link',
      forceLink<SimNode, SimLink>(links)
        .id((d) => d.id)
        .distance((l) => (l.kind === 'member' ? 80 : 220))
        .strength((l) => (l.kind === 'member' ? 0.6 : 0.15))
    );

    sim.alpha(wasEmpty ? 1 : 0.35).restart();
    setHostCount(nodesArray.filter((n) => !n.isSynthetic).length);
  }, [liveHosts, expandedClusters]);

  const getNodeColor = (node: SimNode) => {
    if (node.isCluster) return '#64748b';

    const host = node.host;
    if (!host) return '#8b5cf6'; // synthetic subnet hub with no real gateway host
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

  const drawNodeShape = (ctx: CanvasRenderingContext2D, node: SimNode, isSelected: boolean) => {
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

  const drawNetwork = () => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx) return;

    const rect = canvas.getBoundingClientRect();
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.save();
    ctx.translate(offsetRef.current.x, offsetRef.current.y);
    ctx.scale(scaleRef.current, scaleRef.current);

    // Links: source/target were id strings when handed to forceLink, which
    // resolves and mutates them in place to the actual node objects — so by
    // the time ticks are firing, d.source.x/.y are always current.
    ctx.lineWidth = 1;
    linksRef.current.forEach((link) => {
      const s = link.source as SimNode;
      const t = link.target as SimNode;
      if (typeof s === 'string' || typeof t === 'string') return; // not yet resolved
      ctx.strokeStyle = link.kind === 'anchor' ? '#8b5cf6' : '#374151';
      ctx.globalAlpha = link.kind === 'anchor' ? 0.25 : 0.35;
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(t.x, t.y);
      ctx.stroke();
    });

    ctx.globalAlpha = 1;

    nodeMapRef.current.forEach((node) => {
      if (node.isSynthetic) return;
      const isSelected = node.isCluster ? false : node.host?.ip === selectedHostIp;
      drawNodeShape(ctx, node, isSelected);

      if (showLabels && scaleRef.current > 0.4) {
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
    void rect; // keep for future resize-aware drawing without re-triggering lint
  };

  // The simulation's 'tick' handler is registered once and would otherwise
  // capture the first render's drawNetwork (with its stale showLabels /
  // showServices / selectedHostIp). Route every paint through a ref that is
  // refreshed each render so ticks always run the latest draw.
  const drawRef = useRef(drawNetwork);
  drawRef.current = drawNetwork;

  // Coalesce ticks (and prop-driven redraws) into at most one canvas paint
  // per animation frame.
  function scheduleDraw() {
    if (rafRef.current) return;
    rafRef.current = requestAnimationFrame(() => {
      rafRef.current = null;
      drawRef.current();
    });
  }

  useEffect(() => {
    scheduleDraw();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scale, offset, selectedHostIp, showLabels, showServices, hostCount]);

  const handleNodeClick = (node: SimNode) => {
    if (node.isCluster) {
      setExpandedClusters((prev) => new Set([...prev, node.id]));
      return;
    }
    if (node.host) {
      onHostSelect(node.host);
    }
  };

  const getNodeAt = (x: number, y: number): SimNode | null => {
    const transformedX = (x - offsetRef.current.x) / scaleRef.current;
    const transformedY = (y - offsetRef.current.y) / scaleRef.current;

    let found: SimNode | null = null;
    nodeMapRef.current.forEach((node) => {
      if (found || node.isSynthetic) return;
      const hitRadius = node.isCluster ? 16 : 12;
      const distance = Math.hypot(transformedX - node.x, transformedY - node.y);
      if (distance <= hitRadius) found = node;
    });
    return found;
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;

    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    mouseDownPosRef.current = { x: e.clientX, y: e.clientY };
    const clickedNode = getNodeAt(x, y);

    if (clickedNode) {
      if (clickedNode.isCluster) {
        handleNodeClick(clickedNode);
        return;
      }
      draggedNodeRef.current = clickedNode;
      clickedNode.fx = clickedNode.x;
      clickedNode.fy = clickedNode.y;
      simulationRef.current?.alphaTarget(0.3).restart();
      return;
    }

    setIsDragging(true);
    setDragStart({ x: e.clientX - offset.x, y: e.clientY - offset.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (draggedNodeRef.current && rect) {
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      draggedNodeRef.current.fx = (x - offsetRef.current.x) / scaleRef.current;
      draggedNodeRef.current.fy = (y - offsetRef.current.y) / scaleRef.current;
      scheduleDraw();
      return;
    }
    if (!isDragging) return;
    setOffset({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = (e: React.MouseEvent) => {
    const dragged = draggedNodeRef.current;
    if (dragged) {
      const moved = Math.hypot(
        e.clientX - mouseDownPosRef.current.x,
        e.clientY - mouseDownPosRef.current.y
      );
      dragged.fx = null;
      dragged.fy = null;
      simulationRef.current?.alphaTarget(0);
      draggedNodeRef.current = null;
      if (moved < 5 && dragged.host) {
        onHostSelect(dragged.host);
      }
      return;
    }
    setIsDragging(false);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setScale((prev) => Math.max(0.1, Math.min(3, prev * delta)));
  };

  const resetView = () => {
    setScale(1);
    setOffset({ x: 0, y: 0 });
    setExpandedClusters(new Set());
    simulationRef.current?.alpha(0.6).restart();
  };

  const zoomIn = () => setScale((prev) => Math.min(3, prev * 1.2));
  const zoomOut = () => setScale((prev) => Math.max(0.1, prev / 1.2));

  return (
    <div className={`bg-gray-900 rounded-lg border border-gray-700 flex flex-col h-full ${className ?? ''}`}>
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
          onMouseLeave={handleMouseUp}
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
              <div className="text-xs text-gray-500">Drag a node to pin it; drop to release.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkMap;
