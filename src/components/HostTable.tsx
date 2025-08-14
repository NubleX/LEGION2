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
import { Search } from 'lucide-react';
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
    return h.ip.includes(term) || h.hostname?.toLowerCase().includes(term);
  });

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
      <table className="min-w-full text-sm">
        <thead>
          <tr className="text-left text-gray-400">
            <th className="px-2 py-1">IP</th>
            <th className="px-2 py-1">Hostname</th>
            <th className="px-2 py-1">Discovered</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map(host => (
            <tr
              key={host.ip}
              onClick={() => onHostSelect && onHostSelect(host)}
              className="cursor-pointer hover:bg-gray-700"
            >
              <td className="px-2 py-1">{host.ip}</td>
              <td className="px-2 py-1">{host.hostname || '-'}</td>
              <td className="px-2 py-1">{host.timestamp || '-'}</td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td className="px-2 py-4 text-center text-gray-400" colSpan={3}>
                No hosts
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default HostTable;
