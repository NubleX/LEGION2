// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { AlertTriangle, Network, Shield, Server } from 'lucide-react';
import React, { useState } from 'react';
import useHostStore, { Host } from '../stores/hostStore';
import useServiceStore from '../stores/serviceStore';

interface HostTableProps {
  onHostSelect?: (host: Host) => void;
  className?: string;
}

const HostTable: React.FC<HostTableProps> = React.memo(({ onHostSelect, className = '' }) => {
  // Subscribe to hosts array from store
  const hosts = useHostStore(state => state.hosts);
  const getServices = useServiceStore(state => state.getServices);
  const loadServices = useServiceStore(state => state.loadServices);
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());

  const formatTimestamp = (timestamp?: string) => {
    if (!timestamp) return '-';
    try {
      const date = new Date(timestamp);
      return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return '-';
    }
  };


  const getOSIcon = (osFamily?: string) => {
    if (!osFamily) return <Shield className="w-3 h-3 text-gray-400" />;
    switch (osFamily.toLowerCase()) {
      case 'windows': return <Shield className="w-3 h-3 text-blue-400" />;
      case 'linux': return <Shield className="w-3 h-3 text-green-400" />;
      case 'macos': return <Shield className="w-3 h-3 text-gray-300" />;
      default: return <Shield className="w-3 h-3 text-gray-400" />;
    }
  };

  const toggleHostExpansion = (host: Host) => {
    const newExpanded = new Set(expandedHosts);
    if (newExpanded.has(host.ip)) {
      newExpanded.delete(host.ip);
    } else {
      newExpanded.add(host.ip);
      // Load services when expanding
      loadServices(host.ip).catch(console.error);
    }
    setExpandedHosts(newExpanded);
  };

  const getActiveServiceCount = (hostIp: string) => {
    const services = getServices(hostIp);
    return services.filter(s => s.state === 'open').length;
  };

  const getTotalServiceCount = (hostIp: string) => {
    return getServices(hostIp).length;
  };

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400 border-b border-gray-700">
              <th className="px-3 py-2">IP Address</th>
              <th className="px-3 py-2">Hostname</th>
              <th className="px-3 py-2">Vendor</th>
              <th className="px-3 py-2">OS</th>
              <th className="px-3 py-2">Ports</th>
              <th className="px-3 py-2">Services</th>
              <th className="px-3 py-2">Vulns</th>
              <th className="px-3 py-2">Discovered</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map(host => (
              <tr
                key={host.ip}
                onClick={() => onHostSelect && onHostSelect(host)}
                className="cursor-pointer hover:bg-gray-700 border-b border-gray-800"
              >
                <td className="px-3 py-2">
                  <div className="flex items-center space-x-2">
                    <div className={`w-2 h-2 rounded-full ${host.status === 'up' ? 'bg-green-400' : 'bg-red-400'}`} />
                    <span className="font-mono">{host.ip}</span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <span className="text-gray-300">
                    {host.hostname || '-'}
                  </span>
                </td>
                <td className="px-3 py-2">
                  <span className="text-gray-300">
                    {host.vendor || '-'}
                  </span>
                </td>
                <td className="px-3 py-2">
                  <div className="flex items-center space-x-2">
                    {getOSIcon(host.os_family)}
                    <span className="text-gray-300">
                      {host.os_name || host.os_family || '-'}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="flex items-center space-x-1">
                    <Network className="w-3 h-3 text-blue-400" />
                    <span className="text-white font-medium">
                      {host.port_count ?? 0}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="flex items-center space-x-1">
                    <Server className="w-3 h-3 text-green-400" />
                    <span 
                      className="text-white font-medium cursor-pointer hover:text-green-300"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleHostExpansion(host);
                      }}
                      title="Click to view services"
                    >
                      {getActiveServiceCount(host.ip)}/{getTotalServiceCount(host.ip)}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <div className="flex items-center space-x-1">
                    <AlertTriangle className="w-3 h-3 text-orange-400" />
                    <span className={`font-medium ${(host.vulnerability_count || 0) > 0 ? 'text-orange-400' : 'text-gray-400'}`}>
                      {host.vulnerability_count || 0}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <span className="text-gray-400 text-xs">
                    {formatTimestamp(host.last_seen || host.timestamp)}
                  </span>
                </td>
              </tr>
            ))}
            {hosts.length === 0 && (
              <tr>
                <td className="px-3 py-8 text-center text-gray-400" colSpan={8}>
                  No hosts found
                </td>
              </tr>
            )}
            {/* Expanded service rows */}
            {hosts.map(host => {
              if (!expandedHosts.has(host.ip)) return null;
              const services = getServices(host.ip);
              if (services.length === 0) return null;
              
              return (
                <tr key={`${host.ip}-services`} className="bg-gray-800">
                  <td colSpan={8} className="px-3 py-3">
                    <div className="space-y-2">
                      <div className="text-xs text-gray-400 mb-2">Services:</div>
                      <div className="flex flex-wrap gap-2">
                        {services.map((service, idx) => (
                          <div
                            key={idx}
                            className={`px-2 py-1 rounded text-xs ${
                              service.state === 'open'
                                ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                                : 'bg-gray-700 text-gray-400 border border-gray-600'
                            }`}
                          >
                            <span className="font-mono">{service.port}/{service.protocol}</span>
                            <span className="ml-1">{service.name}</span>
                            {service.cve_count > 0 && (
                              <span className="ml-1 text-orange-400">
                                ({service.cve_count} CVEs)
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
});

HostTable.displayName = 'HostTable';

export default HostTable;
