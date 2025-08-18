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

import React, { useRef, useEffect, useState } from 'react';
import { Network, ZoomIn, ZoomOut, RotateCcw, Eye, EyeOff } from 'lucide-react';
import { listen } from '@tauri-apps/api/event';
import type { Host } from '../stores/hostStore';

interface NetworkMapProps {
  hosts: Host[];
  onHostSelect: (host: Host) => void;
  selectedHostIp?: string;
  className?: string;
}

interface NetworkNode {
  id: string;
  x: number;
  y: number;
  host: Host;
  connections: string[];
  subnet: string;
  role: 'gateway' | 'server' | 'client' | 'unknown';
}

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

  // Determine host role based on ports and IP patterns
  const getHostRole = (host: Host): 'gateway' | 'server' | 'client' | 'unknown' => {
    const ip = host.ip;
    const portCount = host.port_count || 0;
    
    // Gateway patterns (router/firewall)
    if (ip.endsWith('.1') || ip.endsWith('.254')) return 'gateway';
    
    // Server patterns (many open ports)
    if (portCount > 10) return 'server';
    
    // Client patterns (few or no open ports)
    if (portCount <= 3) return 'client';
    
    return 'unknown';
  };

  // Group hosts by subnet for better topology
  const groupBySubnet = (hosts: Host[]) => {
    const subnets = new Map<string, Host[]>();
    
    hosts.forEach(host => {
      const subnet = host.ip.split('.').slice(0, 3).join('.');
      if (!subnets.has(subnet)) {
        subnets.set(subnet, []);
      }
      subnets.get(subnet)!.push(host);
    });
    
    return subnets;
  };

  // Set up canvas with proper DPI scaling
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Get device pixel ratio for sharp rendering
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();

    // Set actual canvas size accounting for device pixel ratio
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;

    // Scale the context to match device pixel ratio
    ctx.scale(dpr, dpr);

    // Set canvas CSS size to maintain layout
    canvas.style.width = rect.width + 'px';
    canvas.style.height = rect.height + 'px';
  }, []);

  // Initialize network layout - update when hosts change
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
    const subnets = groupBySubnet(liveHosts);
    const subnetEntries = Array.from(subnets.entries());
    
    let newNodes: NetworkNode[] = [];

    if (subnetEntries.length === 1) {
      // Single subnet - circular layout
      const [subnet, subnetHosts] = subnetEntries[0];
      const radius = Math.min(centerX, centerY) * 0.6;
      
      subnetHosts.forEach((host, index) => {
        const angle = (index / subnetHosts.length) * 2 * Math.PI;
        newNodes.push({
          id: host.ip,
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
          host,
          connections: [],
          subnet,
          role: getHostRole(host)
        });
      });
    } else {
      // Multiple subnets - hierarchical layout
      const subnetRadius = Math.min(centerX, centerY) * 0.3;
      
      subnetEntries.forEach(([subnet, subnetHosts], subnetIndex) => {
        const subnetAngle = (subnetIndex / subnetEntries.length) * 2 * Math.PI;
        const subnetCenterX = centerX + Math.cos(subnetAngle) * subnetRadius;
        const subnetCenterY = centerY + Math.sin(subnetAngle) * subnetRadius;
        const hostRadius = 80;
        
        subnetHosts.forEach((host, hostIndex) => {
          const hostAngle = (hostIndex / subnetHosts.length) * 2 * Math.PI;
          newNodes.push({
            id: host.ip,
            x: subnetCenterX + Math.cos(hostAngle) * hostRadius,
            y: subnetCenterY + Math.sin(hostAngle) * hostRadius,
            host,
            connections: [],
            subnet,
            role: getHostRole(host)
          });
        });
      });
    }

    setNodes(newNodes);
  }, [liveHosts]);

  // Drawing functions
  const getNodeColor = (host: Host, role: string) => {
    if (host.status === 'down') return '#6b7280'; // gray
    
    // Role-based colors with vulnerability overlay
    const vuln_count = host.vulnerability_count || 0;
    
    if (vuln_count === 0) {
      switch (role) {
        case 'gateway': return '#8b5cf6'; // purple
        case 'server': return '#3b82f6'; // blue
        case 'client': return '#16a34a'; // green
        default: return '#6b7280'; // gray
      }
    }
    
    // Vulnerability-based colors (override role colors)
    if (vuln_count < 5) return '#eab308'; // yellow
    if (vuln_count < 10) return '#ea580c'; // orange
    return '#dc2626'; // red
  };

  const drawNodeShape = (ctx: CanvasRenderingContext2D, node: NetworkNode, isSelected: boolean) => {
    const size = isSelected ? 12 : 8;
    const color = getNodeColor(node.host, node.role);
    
    ctx.fillStyle = color;
    
    switch (node.role) {
      case 'gateway':
        // Draw diamond for gateways
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - size);
        ctx.lineTo(node.x + size, node.y);
        ctx.lineTo(node.x, node.y + size);
        ctx.lineTo(node.x - size, node.y);
        ctx.closePath();
        ctx.fill();
        break;
        
      case 'server':
        // Draw square for servers
        ctx.fillRect(node.x - size/2, node.y - size/2, size, size);
        break;
        
      case 'client':
        // Draw circle for clients
        ctx.beginPath();
        ctx.arc(node.x, node.y, size/2, 0, 2 * Math.PI);
        ctx.fill();
        break;
        
      default:
        // Draw triangle for unknown
        ctx.beginPath();
        ctx.moveTo(node.x, node.y - size);
        ctx.lineTo(node.x - size, node.y + size);
        ctx.lineTo(node.x + size, node.y + size);
        ctx.closePath();
        ctx.fill();
    }
    
    // Selection ring
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

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Apply transforms
    ctx.save();
    ctx.translate(offset.x, offset.y);
    ctx.scale(scale, scale);

    // Draw subnet connections and gateway links
    const subnets = groupBySubnet(nodes.map(n => n.host));
    const gateways = nodes.filter(n => n.role === 'gateway');
    
    // Draw subnet boundaries
    subnets.forEach((_, subnet) => {
      const subnetNodes = nodes.filter(n => n.subnet === subnet);
      if (subnetNodes.length > 1) {
        ctx.strokeStyle = '#374151';
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.2;
        
        // Draw connections between hosts in same subnet
        subnetNodes.forEach(nodeA => {
          subnetNodes.forEach(nodeB => {
            if (nodeA.id !== nodeB.id) {
              ctx.beginPath();
              ctx.moveTo(nodeA.x, nodeA.y);
              ctx.lineTo(nodeB.x, nodeB.y);
              ctx.stroke();
            }
          });
        });
      }
    });
    
    // Draw inter-subnet connections through gateways
    if (gateways.length > 0 && subnets.size > 1) {
      ctx.strokeStyle = '#8b5cf6';
      ctx.lineWidth = 2;
      ctx.globalAlpha = 0.4;
      
      gateways.forEach(gateway => {
        // Connect gateway to other subnet gateways
        gateways.forEach(otherGateway => {
          if (gateway.id !== otherGateway.id && gateway.subnet !== otherGateway.subnet) {
            ctx.beginPath();
            ctx.moveTo(gateway.x, gateway.y);
            ctx.lineTo(otherGateway.x, otherGateway.y);
            ctx.stroke();
          }
        });
      });
    }
    
    ctx.globalAlpha = 1;

    // Draw nodes with role-based shapes
    nodes.forEach(node => {
      const isSelected = node.host.ip === selectedHostIp;
      drawNodeShape(ctx, node, isSelected);

      // Host labels
      if (showLabels && scale > 0.5) {
        ctx.fillStyle = '#f9fafb';
        ctx.font = '10px monospace';
        ctx.textAlign = 'center';
        
        const label = node.host.hostname || node.host.ip;
        const shortLabel = label.length > 15 ? label.substring(0, 12) + '...' : label;
        
        ctx.fillText(shortLabel, node.x, node.y - 15);
        
          // Service count
          if (showServices && (node.host.port_count || 0) > 0) {
            ctx.font = '8px monospace';
            ctx.fillStyle = '#9ca3af';
            ctx.fillText(`${node.host.port_count || 0} ports`, node.x, node.y + 20);
          }
      }
    });

    ctx.restore();
  };

  // Event handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;

    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    // Check for node clicks
    const clickedNode = getNodeAt(x, y);
    if (clickedNode && onHostSelect) {
      onHostSelect(clickedNode.host);
      return;
    }

    // Start dragging
    setIsDragging(true);
    setDragStart({ x: e.clientX - offset.x, y: e.clientY - offset.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;

    setOffset({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setScale(prev => Math.max(0.1, Math.min(3, prev * delta)));
  };

  const getNodeAt = (x: number, y: number): NetworkNode | null => {
    const transformedX = (x - offset.x) / scale;
    const transformedY = (y - offset.y) / scale;

    return nodes.find(node => {
      const distance = Math.sqrt(
        Math.pow(transformedX - node.x, 2) + 
        Math.pow(transformedY - node.y, 2)
      );
      return distance <= 12;
    }) || null;
  };

  const resetView = () => {
    setScale(1);
    setOffset({ x: 0, y: 0 });
  };

  const zoomIn = () => setScale(prev => Math.min(3, prev * 1.2));
  const zoomOut = () => setScale(prev => Math.max(0.1, prev / 1.2));

  // Draw on every update
  useEffect(() => {
    drawNetwork();
  }, [nodes, scale, offset, selectedHostIp, showLabels, showServices]);


  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 flex flex-col h-full">
      {/* Compact Controls Header */}
      <div className="p-2 border-b border-gray-700">
        <div className="flex items-center justify-start">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowLabels(!showLabels)}
              className={`p-2 rounded transition-colors ${
                showLabels ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
              title="Toggle Labels"
            >
              {showLabels ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
            </button>
            
            <button
              onClick={() => setShowServices(!showServices)}
              className={`p-2 rounded transition-colors text-xs px-3 ${
                showServices ? 'bg-green-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
              title="Toggle Service Info"
            >
              SVC
            </button>

            <div className="flex bg-gray-800 rounded">
              <button
                onClick={zoomOut}
                className="p-2 hover:bg-gray-600 rounded-l transition-colors"
                title="Zoom Out"
              >
                <ZoomOut className="w-4 h-4 text-gray-300" />
              </button>
              <button
                onClick={resetView}
                className="p-2 hover:bg-gray-600 transition-colors"
                title="Reset View"
              >
                <RotateCcw className="w-4 h-4 text-gray-300" />
              </button>
              <button
                onClick={zoomIn}
                className="p-2 hover:bg-gray-600 rounded-r transition-colors"
                title="Zoom In"
              >
                <ZoomIn className="w-4 h-4 text-gray-300" />
              </button>
            </div>
          </div>
        </div>

      </div>

      {/* Canvas */}
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

        {/* Legend Toggle */}
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
                  <div className="w-3 h-3 bg-purple-500 transform rotate-45"></div>
                  <span className="text-gray-300">Gateway</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-blue-500"></div>
                  <span className="text-gray-300">Server</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-green-500"></div>
                  <span className="text-gray-300">Client</span>
                </div>
              </div>
              
              <div className="text-xs text-gray-300 mb-1 font-medium">Risk Level</div>
              <div className="space-y-1 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-green-500"></div>
                  <span className="text-gray-300">Secure</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-yellow-500"></div>
                  <span className="text-gray-300">Low Risk</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-red-500"></div>
                  <span className="text-gray-300">Critical</span>
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