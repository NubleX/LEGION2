// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev
//
// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024.
//
// LEGION (https://gotham-security.com)
// Copyright (c) 2023 Gotham Security
//
//     This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
//     License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
//     version.
//
//     This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
//     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//     details.
//
//     You should have received a copy of the GNU General Public License along with this program.
//     If not, see <http://www.gnu.org/licenses/>.

import React, { useState } from 'react';
import { Search, Shield, AlertTriangle, Network } from 'lucide-react';
import useHostStore, { Host } from '../stores/hostStore';

interface HostTableProps {
  onHostSelect?: (host: Host) => void;
  className?: string;
}

const HostTable: React.FC<HostTableProps> = ({ onHostSelect, className = '' }) => {
  const hosts = useHostStore(state => state.hosts);
  const [searchTerm, setSearchTerm] = useState('');

  const filtered = hosts.filter(h => {
    const term = searchTerm.toLowerCase();
    return h.ip.includes(term) || h.hostname?.toLowerCase().includes(term) || h.os_name?.toLowerCase().includes(term);
  });

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

  const getStatusColor = (status?: string) => {
    switch (status) {
      case 'up': return 'text-green-400';
      case 'down': return 'text-red-400';
      default: return 'text-gray-400';
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

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="flex items-center space-x-2">
        <Search className="w-4 h-4 text-gray-400" />
        <input
          type="text"
          placeholder="Search hosts..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          className="flex-1 px-2 py-1 bg-gray-800 text-white rounded"
        />
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400 border-b border-gray-700">
              <th className="px-3 py-2">IP Address</th>
              <th className="px-3 py-2">Hostname</th>
              <th className="px-3 py-2">OS</th>
              <th className="px-3 py-2">Ports</th>
              <th className="px-3 py-2">Vulns</th>
              <th className="px-3 py-2">Discovered</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(host => (
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
                      {host.port_count || 0}
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
            {filtered.length === 0 && (
              <tr>
                <td className="px-3 py-8 text-center text-gray-400" colSpan={6}>
                  No hosts found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default HostTable;
