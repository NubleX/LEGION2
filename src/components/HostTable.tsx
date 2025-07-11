// Enhanced HostTable.tsx - Integrates with database and optimized scanning
// Copyright (c) 2025 NubleX / Igor Dunaev

import React, { useState, useEffect, useMemo } from 'react';
import { 
  Server, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Search,
  Trash2,
  RefreshCw,
  Eye,
  Wifi,
  Shield
} from 'lucide-react';
import useHostStore, { Host } from '../stores/hostStore';

interface HostTableProps {
  onHostSelect: (host: Host) => void;
  showActions?: boolean;
  selectedHostId?: string;
  className?: string;
}

const EnhancedHostTable: React.FC<HostTableProps> = ({ 
  onHostSelect, 
  showActions = true, 
  selectedHostId,
  className = ""
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'up' | 'down' | 'unknown' | 'scanning'>('all');
  const [sortField, setSortField] = useState<keyof Host>('last_seen');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set());

  const {
    hosts,
    filteredHosts,
    isLoading,
    lastError,
    loadHosts,
    deleteHost,
    deleteMultipleHosts,
    refreshHost,
    setFilter
  } = useHostStore();

  // Load hosts on component mount
  useEffect(() => {
    if (loadHosts) {
      loadHosts();
    }
  }, [loadHosts]);

  // Apply search and filters
  useEffect(() => {
    const filters: any = {};
    
    if (statusFilter !== 'all') {
      filters.status = statusFilter;
    }
    
    if (searchTerm) {
      filters.search_term = searchTerm;
    }
    
    if (setFilter) {
      setFilter(filters);
    }
  }, [searchTerm, statusFilter, setFilter]);

  // Sorted and filtered hosts
  const sortedHosts = useMemo(() => {
    if (!filteredHosts) return [];
    
    const sorted = [...filteredHosts].sort((a, b) => {
      const aValue = a[sortField];
      const bValue = b[sortField];
      
      if (typeof aValue === 'string' && typeof bValue === 'string') {
        return sortDirection === 'asc' 
          ? aValue.localeCompare(bValue)
          : bValue.localeCompare(aValue);
      }
      
      if (typeof aValue === 'number' && typeof bValue === 'number') {
        return sortDirection === 'asc' ? aValue - bValue : bValue - aValue;
      }
      
      return 0;
    });
    
    return sorted;
  }, [filteredHosts, sortField, sortDirection]);

  const handleSort = (field: keyof Host) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const handleHostSelect = (host: Host) => {
    onHostSelect(host);
  };

  const handleHostToggle = (hostId: string) => {
    const newSelected = new Set(selectedHosts);
    if (newSelected.has(hostId)) {
      newSelected.delete(hostId);
    } else {
      newSelected.add(hostId);
    }
    setSelectedHosts(newSelected);
  };

  const handleDeleteSelected = async () => {
    if (selectedHosts.size === 0) return;
    
    if (confirm(`Delete ${selectedHosts.size} selected hosts?`)) {
      try {
        if (deleteMultipleHosts) {
          await deleteMultipleHosts(Array.from(selectedHosts));
        }
        setSelectedHosts(new Set());
      } catch (error) {
        console.error('Failed to delete hosts:', error);
      }
    }
  };

  const handleDeleteHost = async (hostId: string, event: React.MouseEvent) => {
    event.stopPropagation();
    
    if (confirm('Delete this host and all associated data?')) {
      try {
        if (deleteHost) {
          await deleteHost(hostId);
        }
      } catch (error) {
        console.error('Failed to delete host:', error);
      }
    }
  };

  const handleRefreshHost = async (hostId: string, event: React.MouseEvent) => {
    event.stopPropagation();
    
    try {
      if (refreshHost) {
        await refreshHost(hostId);
      }
    } catch (error) {
      console.error('Failed to refresh host:', error);
    }
  };

  const getStatusIcon = (status: Host['status']) => {
    switch (status) {
      case 'up':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'down':
        return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'scanning':
        return <Activity className="w-4 h-4 text-yellow-400 animate-pulse" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getVulnerabilityColor = (count: number) => {
    if (count === 0) return 'text-green-400';
    if (count < 5) return 'text-yellow-400';
    if (count < 10) return 'text-orange-400';
    return 'text-red-400';
  };

  const formatLastSeen = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return `${Math.floor(diffMins / 1440)}d ago`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center space-x-2 text-gray-400">
          <Activity className="w-5 h-5 animate-spin" />
          <span>Loading hosts...</span>
        </div>
      </div>
    );
  }

  if (lastError) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center text-red-400">
          <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
          <p className="text-sm">{lastError}</p>
          <button 
            onClick={() => loadHosts && loadHosts()}
            className="mt-2 px-3 py-1 bg-red-600 text-white rounded text-xs hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`flex flex-col h-full ${className}`}>
      {/* Search and Filter Controls */}
      <div className="p-4 space-y-3 border-b border-gray-700">
        {/* Search Bar */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search hosts by IP, hostname, or OS..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Filters and Actions */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="px-3 py-1 bg-gray-700 border border-gray-600 rounded text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Status</option>
              <option value="up">Up</option>
              <option value="down">Down</option>
              <option value="scanning">Scanning</option>
              <option value="unknown">Unknown</option>
            </select>

            {/* Results Count */}
            <span className="text-sm text-gray-400">
              {sortedHosts.length} hosts
            </span>
          </div>

          {/* Action Buttons */}
          {showActions && (
            <div className="flex items-center space-x-2">
              {selectedHosts.size > 0 && (
                <button
                  onClick={handleDeleteSelected}
                  className="px-3 py-1 bg-red-600 text-white rounded text-sm hover:bg-red-700 flex items-center space-x-1"
                >
                  <Trash2 className="w-3 h-3" />
                  <span>Delete ({selectedHosts.size})</span>
                </button>
              )}
              
              <button
                onClick={() => loadHosts && loadHosts()}
                className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 flex items-center space-x-1"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Refresh</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Host Table */}
      <div className="flex-1 overflow-auto">
        {sortedHosts.length === 0 ? (
          <div className="flex items-center justify-center h-64">
            <div className="text-center text-gray-400">
              <Server className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p className="text-lg mb-1">No Hosts Found</p>
              <p className="text-sm">Start a scan to discover network hosts</p>
            </div>
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-800 sticky top-0">
              <tr>
                {showActions && (
                  <th className="w-8 p-3 text-left">
                    <input
                      type="checkbox"
                      checked={selectedHosts.size === sortedHosts.length && sortedHosts.length > 0}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedHosts(new Set(sortedHosts.map(h => h.id)));
                        } else {
                          setSelectedHosts(new Set());
                        }
                      }}
                      className="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                    />
                  </th>
                )}
                <th 
                  className="p-3 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                  onClick={() => handleSort('status')}
                >
                  Status
                </th>
                <th 
                  className="p-3 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                  onClick={() => handleSort('ip')}
                >
                  IP Address
                </th>
                <th 
                  className="p-3 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                  onClick={() => handleSort('hostname')}
                >
                  Hostname
                </th>
                <th 
                  className="p-3 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                  onClick={() => handleSort('os_name')}
                >
                  Operating System
                </th>
                <th 
                  className="p-3 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                  onClick={() => handleSort('port_count')}
                >
                  Ports
                </th>
                <th 
                  className="p-3 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                  onClick={() => handleSort('vulnerability_count')}
                >
                  Vulnerabilities
                </th>
                <th 
                  className="p-3 text-left text-sm font-medium text-gray-300 cursor-pointer hover:text-white"
                  onClick={() => handleSort('last_seen')}
                >
                  Last Seen
                </th>
                {showActions && (
                  <th className="p-3 text-left text-sm font-medium text-gray-300">
                    Actions
                  </th>
                )}
              </tr>
            </thead>
            <tbody>
              {sortedHosts.map((host) => (
                <tr
                  key={host.id}
                  onClick={() => handleHostSelect(host)}
                  className={`border-b border-gray-700 hover:bg-gray-800 cursor-pointer transition-colors ${
                    selectedHostId === host.id ? 'bg-blue-900/30 border-blue-500' : ''
                  }`}
                >
                  {showActions && (
                    <td className="p-3">
                      <input
                        type="checkbox"
                        checked={selectedHosts.has(host.id)}
                        onChange={() => handleHostToggle(host.id)}
                        onClick={(e) => e.stopPropagation()}
                        className="rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500"
                      />
                    </td>
                  )}
                  <td className="p-3">
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(host.status)}
                      <span className="text-sm capitalize text-gray-300">
                        {host.status}
                      </span>
                    </div>
                  </td>
                  <td className="p-3">
                    <span className="font-mono text-white font-medium">
                      {host.ip}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className="text-gray-300">
                      {host.hostname || '-'}
                    </span>
                  </td>
                  <td className="p-3">
                    <div className="flex items-center space-x-2">
                      {host.os_name && (
                        <>
                          <Shield className="w-3 h-3 text-gray-400" />
                          <span className="text-gray-300 text-sm">
                            {host.os_name}
                          </span>
                          {host.os_accuracy && (
                            <span className="text-xs text-gray-500">
                              ({host.os_accuracy}%)
                            </span>
                          )}
                        </>
                      )}
                      {!host.os_name && (
                        <span className="text-gray-500 text-sm">Unknown</span>
                      )}
                    </div>
                  </td>
                  <td className="p-3">
                    <div className="flex items-center space-x-2">
                      <Wifi className="w-3 h-3 text-blue-400" />
                      <span className="text-white font-medium">
                        {host.port_count || 0}
                      </span>
                      {host.port_count > 0 && (
                        <span className="text-xs bg-blue-600 px-1 py-0.5 rounded text-white">
                          open
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="p-3">
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className={`w-3 h-3 ${getVulnerabilityColor(host.vulnerability_count || 0)}`} />
                      <span className={`font-medium ${getVulnerabilityColor(host.vulnerability_count || 0)}`}>
                        {host.vulnerability_count || 0}
                      </span>
                      {host.vulnerability_count > 0 && (
                        <span className="text-xs bg-red-600 px-1 py-0.5 rounded text-white">
                          {host.vulnerability_count >= 10 ? 'critical' : 'medium'}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="p-3">
                    <span className="text-gray-400 text-sm">
                      {formatLastSeen(host.last_seen)}
                    </span>
                  </td>
                  {showActions && (
                    <td className="p-3">
                      <div className="flex items-center space-x-1">
                        <button
                          onClick={(e) => handleRefreshHost(host.id, e)}
                          className="p-1 text-gray-400 hover:text-blue-400 transition-colors"
                          title="Refresh host data"
                        >
                          <RefreshCw className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => handleHostSelect(host)}
                          className="p-1 text-gray-400 hover:text-green-400 transition-colors"
                          title="View details"
                        >
                          <Eye className="w-3 h-3" />
                        </button>
                        <button
                          onClick={(e) => handleDeleteHost(host.id, e)}
                          className="p-1 text-gray-400 hover:text-red-400 transition-colors"
                          title="Delete host"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Summary Footer */}
      {sortedHosts.length > 0 && (
        <div className="p-3 border-t border-gray-700 bg-gray-800 text-sm text-gray-400">
          <div className="flex items-center justify-between">
            <span>
              Showing {sortedHosts.length} of {hosts?.length || 0} hosts
            </span>
            <div className="flex items-center space-x-4">
              <span className="flex items-center space-x-1">
                <CheckCircle className="w-3 h-3 text-green-400" />
                <span>{sortedHosts.filter(h => h.status === 'up').length} up</span>
              </span>
              <span className="flex items-center space-x-1">
                <AlertTriangle className="w-3 h-3 text-red-400" />
                <span>{sortedHosts.filter(h => h.status === 'down').length} down</span>
              </span>
              <span className="flex items-center space-x-1">
                <Wifi className="w-3 h-3 text-blue-400" />
                <span>{sortedHosts.reduce((sum, h) => sum + (h.port_count || 0), 0)} ports</span>
              </span>
              <span className="flex items-center space-x-1">
                <Shield className="w-3 h-3 text-yellow-400" />
                <span>{sortedHosts.reduce((sum, h) => sum + (h.vulnerability_count || 0), 0)} vulns</span>
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EnhancedHostTable;