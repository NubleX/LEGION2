// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import React, { useState, useMemo } from 'react';
import { AlertTriangle, RefreshCw, Search, Filter } from 'lucide-react';
import type { ServiceInfo } from '../types/services';
import useServiceStore from '../stores/serviceStore';

interface ServiceTableProps {
  hostIp: string;
  onServiceSelect?: (service: ServiceInfo) => void;
  className?: string;
}

const ServiceTable: React.FC<ServiceTableProps> = ({ hostIp, onServiceSelect, className = '' }) => {
  const services = useServiceStore((state) => state.getServices(hostIp));
  const loading = useServiceStore((state) => state.loading[hostIp] || false);
  const loadServiceCves = useServiceStore((state) => state.loadServiceCves);
  const getServiceCves = useServiceStore((state) => state.getServiceCves);

  const [filterState, setFilterState] = useState<'all' | 'open' | 'closed'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'port' | 'name' | 'cve_count'>('port');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [expandedServices, setExpandedServices] = useState<Set<string>>(new Set());

  const filteredAndSortedServices = useMemo(() => {
    let filtered = services.filter((service) => {
      // Filter by state
      if (filterState === 'open' && service.state !== 'open') return false;
      if (filterState === 'closed' && service.state === 'open') return false;

      // Filter by search query
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          service.name.toLowerCase().includes(query) ||
          service.port.toString().includes(query) ||
          service.version?.toLowerCase().includes(query) ||
          false
        );
      }

      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      let comparison = 0;
      switch (sortBy) {
        case 'port':
          comparison = a.port - b.port;
          break;
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'cve_count':
          comparison = a.cve_count - b.cve_count;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [services, filterState, searchQuery, sortBy, sortOrder]);

  const toggleServiceExpansion = (service: ServiceInfo) => {
    const key = `${service.port}/${service.protocol}`;
    const newExpanded = new Set(expandedServices);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
      // Load CVEs when expanding
      loadServiceCves(hostIp, service.port, service.name).catch(console.error);
    }
    setExpandedServices(newExpanded);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStateColor = (state: string) => {
    switch (state.toLowerCase()) {
      case 'open': return 'bg-green-600';
      case 'closed': return 'bg-red-600';
      case 'filtered': return 'bg-yellow-600';
      default: return 'bg-gray-600';
    }
  };

  if (loading && services.length === 0) {
    return (
      <div className={`text-center py-8 text-gray-400 ${className}`}>
        <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin" />
        <p>Loading services...</p>
      </div>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Filters and Search */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 flex-1">
          <Search className="w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search services..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <select
            value={filterState}
            onChange={(e) => setFilterState(e.target.value as 'all' | 'open' | 'closed')}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="all">All States</option>
            <option value="open">Open Only</option>
            <option value="closed">Closed Only</option>
          </select>
        </div>
        <select
          value={`${sortBy}-${sortOrder}`}
          onChange={(e) => {
            const [by, order] = e.target.value.split('-');
            setSortBy(by as 'port' | 'name' | 'cve_count');
            setSortOrder(order as 'asc' | 'desc');
          }}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="port-asc">Port ↑</option>
          <option value="port-desc">Port ↓</option>
          <option value="name-asc">Name ↑</option>
          <option value="name-desc">Name ↓</option>
          <option value="cve_count-desc">CVEs ↓</option>
          <option value="cve_count-asc">CVEs ↑</option>
        </select>
      </div>

      {/* Services Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400 border-b border-gray-700">
              <th className="px-3 py-2">Port/Protocol</th>
              <th className="px-3 py-2">Service</th>
              <th className="px-3 py-2">Version</th>
              <th className="px-3 py-2">State</th>
              <th className="px-3 py-2">CVEs</th>
              <th className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredAndSortedServices.length === 0 ? (
              <tr>
                <td className="px-3 py-8 text-center text-gray-400" colSpan={6}>
                  No services found
                </td>
              </tr>
            ) : (
              filteredAndSortedServices.map((service) => {
                const key = `${service.port}/${service.protocol}`;
                const isExpanded = expandedServices.has(key);
                const cves = getServiceCves(hostIp, service.port);

                return (
                  <React.Fragment key={key}>
                    <tr
                      onClick={() => onServiceSelect && onServiceSelect(service)}
                      className={`cursor-pointer hover:bg-gray-700 border-b border-gray-800 ${
                        isExpanded ? 'bg-gray-800' : ''
                      }`}
                    >
                      <td className="px-3 py-2">
                        <span className="font-mono text-white">
                          {service.port}/{service.protocol}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-gray-300">{service.name}</span>
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-gray-400 text-xs">
                          {service.version || '-'}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`px-2 py-1 text-white text-xs rounded font-medium ${getStateColor(
                            service.state
                          )}`}
                        >
                          {service.state}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        {service.cve_count > 0 ? (
                          <div className="flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-orange-400" />
                            <span className="text-orange-400 font-medium">
                              {service.cve_count}
                            </span>
                          </div>
                        ) : (
                          <span className="text-gray-500">0</span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleServiceExpansion(service);
                          }}
                          className="text-blue-400 hover:text-blue-300 text-xs"
                        >
                          {isExpanded ? 'Hide' : 'Show'} Details
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-gray-900">
                        <td colSpan={6} className="px-3 py-4">
                          <div className="space-y-3">
                            {service.banner && (
                              <div>
                                <span className="text-gray-400 text-xs">Banner:</span>
                                <code className="block mt-1 bg-gray-800 px-2 py-1 rounded text-xs text-gray-300">
                                  {service.banner}
                                </code>
                              </div>
                            )}
                            {cves.length > 0 && (
                              <div>
                                <span className="text-gray-400 text-xs mb-2 block">
                                  CVEs ({cves.length}):
                                </span>
                                <div className="space-y-2">
                                  {cves.map((cve) => (
                                    <div
                                      key={cve.id}
                                      className={`p-2 rounded border text-xs ${getSeverityColor(
                                        cve.severity
                                      )}`}
                                    >
                                      <div className="flex items-center justify-between">
                                        <span className="font-semibold">{cve.name}</span>
                                        {cve.cvss_score && (
                                          <span className="text-gray-400">
                                            CVSS: {cve.cvss_score}
                                          </span>
                                        )}
                                      </div>
                                      {cve.description && (
                                        <p className="mt-1 text-gray-300">{cve.description}</p>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {service.enrichment_status === 'none' && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  // TODO: Trigger OSINT enrichment
                                  console.log('Enrich service:', service);
                                }}
                                className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded"
                              >
                                Enrich with OSINT
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ServiceTable;

