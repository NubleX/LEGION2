import React, { useState, useEffect, useMemo } from 'react';
import { Monitor, Shield, AlertTriangle, Search, Filter, Download, Trash2, Eye } from 'lucide-react';
import useHostStore from '../stores/hostStore';
import type { Host, HostFilter } from '../types/scanning';

interface HostTableProps {
  onHostSelect?: (host: Host) => void;
  showActions?: boolean;
}

const HostTable: React.FC<HostTableProps> = ({ 
  onHostSelect, 
  showActions = true 
}) => {
  const {
    filteredHosts,
    currentFilter,
    isLoading,
    lastError,
    loadHosts,
    loadHostDetails,
    setFilter,
    clearFilter,
    deleteHost,
    exportHosts
  } = useHostStore();

  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    loadHosts();
  }, [loadHosts]);

  const getSeverityColor = (count: number) => {
    if (count === 0) return 'text-green-400';
    if (count < 5) return 'text-yellow-400';
    if (count < 10) return 'text-orange-400';
    return 'text-red-400';
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'up': return 'text-green-400';
      case 'down': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const handleSearch = (term: string) => {
    setSearchTerm(term);
    setFilter({ ...currentFilter, search_term: term });
  };

  const handleFilterChange = (newFilter: Partial<HostFilter>) => {
    setFilter({ ...currentFilter, ...newFilter });
  };

  const handleSelectAll = (checked: boolean) => {
    setSelectedHosts(checked ? filteredHosts.map(h => h.id) : []);
  };

  const handleSelectHost = (hostId: string, checked: boolean) => {
    setSelectedHosts(prev => 
      checked 
        ? [...prev, hostId]
        : prev.filter(id => id !== hostId)
    );
  };

  const handleExport = async () => {
    try {
      const data = await exportHosts('json');
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'hosts.json';
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  const handleDelete = async (hostId: string) => {
    if (window.confirm('Delete this host and all associated data?')) {
      await deleteHost(hostId);
    }
  };

  const FilterPanel = () => (
    <div className="bg-gray-800 p-4 rounded border border-gray-600 mb-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-sm text-gray-300 mb-1">Status</label>
          <select
            value={currentFilter.status || ''}
            onChange={(e) => handleFilterChange({ status: e.target.value as any || undefined })}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white"
          >
            <option value="">All</option>
            <option value="up">Up</option>
            <option value="down">Down</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>

        <div>
          <label className="block text-sm text-gray-300 mb-1">Has Vulnerabilities</label>
          <select
            value={currentFilter.has_vulnerabilities?.toString() || ''}
            onChange={(e) => handleFilterChange({ 
              has_vulnerabilities: e.target.value ? e.target.value === 'true' : undefined 
            })}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white"
          >
            <option value="">All</option>
            <option value="true">With Vulnerabilities</option>
            <option value="false">Clean</option>
          </select>
        </div>

        <div>
          <label className="block text-sm text-gray-300 mb-1">OS Family</label>
          <select
            value={currentFilter.os_family || ''}
            onChange={(e) => handleFilterChange({ os_family: e.target.value || undefined })}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded text-white"
          >
            <option value="">All</option>
            <option value="Linux">Linux</option>
            <option value="Windows">Windows</option>
            <option value="macOS">macOS</option>
            <option value="FreeBSD">FreeBSD</option>
          </select>
        </div>
      </div>

      <div className="flex gap-2 mt-4">
        <button
          onClick={clearFilter}
          className="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded transition-colors"
        >
          Clear Filters
        </button>
      </div>
    </div>
  );

  if (isLoading) {
    return (
      <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400"></div>
          <span className="ml-3 text-gray-300">Loading hosts...</span>
        </div>
      </div>
    );
  }

  if (lastError) {
    return (
      <div className="bg-gray-900 p-6 rounded-lg border border-red-500">
        <div className="flex items-center text-red-400">
          <AlertTriangle className="w-5 h-5 mr-2" />
          Error: {lastError}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="p-6 border-b border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <Monitor className="w-5 h-5 text-blue-400" />
            Discovered Hosts ({filteredHosts.length})
          </h2>

          {showActions && (
            <div className="flex gap-2">
              <button
                onClick={() => setShowFilters(!showFilters)}
                className="p-2 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                title="Toggle Filters"
              >
                <Filter className="w-4 h-4 text-gray-300" />
              </button>
              <button
                onClick={handleExport}
                className="p-2 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                title="Export Hosts"
              >
                <Download className="w-4 h-4 text-gray-300" />
              </button>
            </div>
          )}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search hosts by IP, hostname, or OS..."
            value={searchTerm}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Filters */}
      {showFilters && <div className="p-6 border-b border-gray-700"><FilterPanel /></div>}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-800 border-b border-gray-700">
            <tr>
              {showActions && (
                <th className="px-4 py-3 text-left">
                  <input
                    type="checkbox"
                    checked={selectedHosts.length === filteredHosts.length && filteredHosts.length > 0}
                    onChange={(e) => handleSelectAll(e.target.checked)}
                    className="rounded bg-gray-700 border-gray-600"
                  />
                </th>
              )}
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Status</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">IP Address</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Hostname</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">OS</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Ports</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Vulnerabilities</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Last Seen</th>
              {showActions && (
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Actions</th>
              )}
            </tr>
          </thead>
          <tbody>
            {filteredHosts.length === 0 ? (
              <tr>
                <td 
                  colSpan={showActions ? 9 : 7} 
                  className="px-4 py-8 text-center text-gray-400"
                >
                  No hosts found. Start a scan to discover hosts.
                </td>
              </tr>
            ) : (
              filteredHosts.map((host) => (
                <tr 
                  key={host.id} 
                  className="border-b border-gray-700 hover:bg-gray-800 transition-colors cursor-pointer"
                  onClick={() => onHostSelect?.(host)}
                >
                  {showActions && (
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedHosts.includes(host.id)}
                        onChange={(e) => {
                          e.stopPropagation();
                          handleSelectHost(host.id, e.target.checked);
                        }}
                        className="rounded bg-gray-700 border-gray-600"
                      />
                    </td>
                  )}
                  <td className="px-4 py-3">
                    <span className={`font-medium ${getStatusColor(host.status)}`}>
                      ●
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white font-mono">{host.ip}</td>
                  <td className="px-4 py-3 text-gray-300">{host.hostname || '-'}</td>
                  <td className="px-4 py-3 text-gray-300">
                    {host.os_name ? (
                      <div>
                        <div className="text-sm">{host.os_name}</div>
                        {host.os_accuracy && (
                          <div className="text-xs text-gray-500">{host.os_accuracy}% confidence</div>
                        )}
                      </div>
                    ) : '-'}
                  </td>
                  <td className="px-4 py-3 text-gray-300">{host.port_count}</td>
                  <td className="px-4 py-3">
                    <span className={`font-medium ${getSeverityColor(host.vulnerability_count)}`}>
                      {host.vulnerability_count}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-300 text-sm">
                    {new Date(host.last_seen).toLocaleDateString()}
                  </td>
                  {showActions && (
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            loadHostDetails(host.id);
                          }}
                          className="p-1 hover:bg-gray-700 rounded transition-colors"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4 text-gray-400" />
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDelete(host.id);
                          }}
                          className="p-1 hover:bg-gray-700 rounded transition-colors"
                          title="Delete Host"
                        >
                          <Trash2 className="w-4 h-4 text-red-400" />
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default HostTable;