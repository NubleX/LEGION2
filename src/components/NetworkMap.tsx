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
import type { Host } from '../stores/hostStore';

interface NetworkMapProps {
  hosts: Host[];
  onHostSelect: (host: Host) => void;
  selectedHostId?: string;
  className?: string;
}

interface NetworkNode {
  id: string;
  x: number;
  y: number;
  host: Host;
  connections: string[];
}

const NetworkMap: React.FC<NetworkMapProps> = ({ hosts, onHostSelect, selectedHostId }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<NetworkNode[]>([]);
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [showLabels, setShowLabels] = useState(true);
  const [showServices, setShowServices] = useState(false);

  // Initialize network layout
  useEffect(() => {
    if (hosts.length === 0) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) * 0.6;

    // Create nodes in circular layout
    const newNodes: NetworkNode[] = hosts.map((host: Host, index: number) => {
      const angle = (index / hosts.length) * 2 * Math.PI;
      return {
        id: host.id,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        host,
        connections: [] // Would be populated based on network topology
      };
    });

    setNodes(newNodes);
  }, [hosts]);

  // Drawing functions
  const getNodeColor = (host: Host) => {
    if (host.status === 'down') return '#6b7280'; // gray
    
    const vuln_count = host.vulnerability_count || 0;
    
    if (vuln_count === 0) return '#16a34a'; // green
    if (vuln_count < 5) return '#eab308'; // yellow
    if (vuln_count < 10) return '#ea580c'; // orange
    return '#dc2626'; // red
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

    // Draw connections (simple example - same subnet)
    ctx.strokeStyle = '#374151';
    ctx.lineWidth = 1;
    
    nodes.forEach(nodeA => {
      nodes.forEach(nodeB => {
        if (nodeA.id !== nodeB.id) {
          const ipA = nodeA.host.ip.split('.').slice(0, 3).join('.');
          const ipB = nodeB.host.ip.split('.').slice(0, 3).join('.');
          
          if (ipA === ipB) { // Same subnet
            ctx.beginPath();
            ctx.moveTo(nodeA.x, nodeA.y);
            ctx.lineTo(nodeB.x, nodeB.y);
            ctx.globalAlpha = 0.3;
            ctx.stroke();
            ctx.globalAlpha = 1;
          }
        }
      });
    });

    // Draw nodes
    nodes.forEach(node => {
      const isSelected = node.host.id === selectedHostId;
      const color = getNodeColor(node.host);
      
      // Node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, isSelected ? 12 : 8, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      
      // Selection ring
      if (isSelected) {
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Host labels
      if (showLabels && scale > 0.5) {
        ctx.fillStyle = '#f9fafb';
        ctx.font = '10px monospace';
        ctx.textAlign = 'center';
        
        const label = node.host.hostname || node.host.ip;
        const shortLabel = label.length > 15 ? label.substring(0, 12) + '...' : label;
        
        ctx.fillText(shortLabel, node.x, node.y - 15);
        
        // Service count
        if (showServices && node.host.port_count > 0) {
          ctx.font = '8px monospace';
          ctx.fillStyle = '#9ca3af';
          ctx.fillText(`${node.host.port_count} ports`, node.x, node.y + 20);
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
  }, [nodes, scale, offset, selectedHostId, showLabels, showServices]);

  const getStatsColor = (count: number, type: 'vulnerabilities' | 'hosts') => {
    if (type === 'vulnerabilities') {
      if (count === 0) return 'text-green-400';
      if (count < 5) return 'text-yellow-400';
      return 'text-red-400';
    }
    return 'text-blue-400';
  };

  const totalVulns = hosts.reduce((sum: number, host: Host) => sum + (host.vulnerability_count || 0), 0);
  const upHosts = hosts.filter((h: Host) => h.status === 'up').length;
  const totalPorts = hosts.reduce((sum: number, host: Host) => sum + (host.port_count || 0), 0);

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Network className="w-5 h-5 text-purple-400" />
            Network Topology
          </h2>

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

        {/* Network Stats */}
        <div className="grid grid-cols-4 gap-4 text-sm">
          <div className="bg-gray-800 p-2 rounded">
            <div className="text-gray-400">Hosts</div>
            <div className={getStatsColor(upHosts, 'hosts')}>{upHosts}/{hosts.length}</div>
          </div>
          <div className="bg-gray-800 p-2 rounded">
            <div className="text-gray-400">Open Ports</div>
            <div className="text-green-400">{totalPorts}</div>
          </div>
          <div className="bg-gray-800 p-2 rounded">
            <div className="text-gray-400">Vulnerabilities</div>
            <div className={getStatsColor(totalVulns, 'vulnerabilities')}>{totalVulns}</div>
          </div>
          <div className="bg-gray-800 p-2 rounded">
            <div className="text-gray-400">Zoom</div>
            <div className="text-gray-300">{Math.round(scale * 100)}%</div>
          </div>
        </div>
      </div>

      {/* Canvas */}
      <div className="relative">
        <canvas
          ref={canvasRef}
          width={800}
          height={500}
          className="w-full cursor-grab active:cursor-grabbing"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onWheel={handleWheel}
        />

        {hosts.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-gray-400">
            <div className="text-center">
              <Network className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>No hosts to display</p>
              <p className="text-sm">Start a scan to discover network topology</p>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-gray-800/90 p-3 rounded border border-gray-600">
          <div className="text-xs text-gray-300 mb-2 font-medium">Host Status</div>
          <div className="space-y-1 text-xs">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="text-gray-300">Secure</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <span className="text-gray-300">Low/Medium Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-orange-500"></div>
              <span className="text-gray-300">High Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <span className="text-gray-300">Critical Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-gray-500"></div>
              <span className="text-gray-300">Offline</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkMap;