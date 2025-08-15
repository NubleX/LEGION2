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


import { AlertTriangle, Download, Search, Shield, Network, Server } from 'lucide-react';
import React, { useMemo, useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import useAppStore from '../stores/appStore';
import useHostStore, { type Host } from '../stores/hostStore';

interface PortInfo {
  number: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
  banner?: string;
}

interface ResultViewerProps {
  selectedScanId?: string;
  selectedHost?: Host;
  className?: string;
}

const ResultViewer: React.FC<ResultViewerProps> = ({ selectedScanId, selectedHost }) => {
  const { vulnerabilities } = useAppStore();
  const hosts = useHostStore(state => state.hosts);
  
  const [selectedTab, setSelectedTab] = useState<'ports' | 'vulnerabilities' | 'details'>('ports');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [hostPorts, setHostPorts] = useState<PortInfo[]>([]);
  const [loadingPorts, setLoadingPorts] = useState(false);

  // Get the host either from selectedHost prop or by selectedScanId (treating it as host ID)
  const currentHost = selectedHost || (selectedScanId ? hosts.find(h => h.id === selectedScanId) : null);

  // Load ports when host changes
  useEffect(() => {
    if (currentHost?.ip) {
      setLoadingPorts(true);
      invoke<PortInfo[]>('get_host_ports_detailed', { hostIp: currentHost.ip })
        .then(setHostPorts)
        .catch(err => {
          console.error('Failed to load ports:', err);
          setHostPorts([]);
        })
        .finally(() => setLoadingPorts(false));
    } else {
      setHostPorts([]);
    }
  }, [currentHost?.ip]);

  const allVulnerabilities = useMemo(() => {
    if (!currentHost || !vulnerabilities) return [];
    
    // Filter vulnerabilities for the current host
    const hostVulns = vulnerabilities.filter(vuln => vuln.host_ip === currentHost.ip);
    
    return hostVulns.filter((vuln: any) => {
      if (severityFilter !== 'all' && vuln.severity.toLowerCase() !== severityFilter) return false;
      if (searchTerm && !vuln.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
  }, [currentHost, vulnerabilities, severityFilter, searchTerm]);

  const allPorts = useMemo(() => {
    if (!hostPorts) return [];
    
    return hostPorts.filter(port =>
      searchTerm === '' ||
      port.number.toString().includes(searchTerm) ||
      port.protocol.toLowerCase().includes(searchTerm.toLowerCase()) ||
      port.service?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      port.state.toLowerCase().includes(searchTerm.toLowerCase())
    );
  }, [hostPorts, searchTerm]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getPortStateColor = (state: string) => {
    switch (state) {
      case 'open': return 'text-green-400';
      case 'closed': return 'text-red-400';
      case 'filtered': return 'text-yellow-400';
      default: return 'text-gray-400';
    }
  };

  const exportResults = () => {
    const data = {
      host: currentHost,
      vulnerabilities: allVulnerabilities,
      ports: allPorts,
      export_time: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'scan-results.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!currentHost) {
    return (
      <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
        <div className="text-center py-8 text-gray-400">
          <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
          <p>No host selected. Select a host to see results here.</p>
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
            <Shield className="w-5 h-5 text-yellow-400" />
            Target Information
          </h2>
          <button
            onClick={exportResults}
            className="flex items-center gap-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>

        {/* Tabs */}
        <div className="flex space-x-1 bg-gray-800 rounded-lg p-1">
          {(['ports', 'vulnerabilities', 'details'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setSelectedTab(tab)}
              className={`px-4 py-2 rounded transition-colors capitalize ${selectedTab === tab
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
                }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {/* Search and Filter */}
        <div className="flex gap-4 mb-6">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder={`Search ${selectedTab}...`}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {selectedTab === 'vulnerabilities' && (
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          )}
        </div>

        {/* Tab Content */}
        {selectedTab === 'ports' && (
          <div className="space-y-4">
            {loadingPorts ? (
              <p className="text-gray-400 text-center py-8">Loading ports...</p>
            ) : allPorts.length === 0 ? (
              <p className="text-gray-400 text-center py-8">No ports found.</p>
            ) : (
              <div className="grid gap-4">
                {allPorts.map((port: PortInfo, index: number) => (
                  <div key={`${port.number}-${port.protocol}-${index}`} className="bg-gray-800 p-4 rounded border border-gray-600">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <span className="text-lg font-mono text-white">
                          {port.number}/{port.protocol}
                        </span>
                        <span className={`px-2 py-1 text-white text-xs rounded font-medium ${
                          port.state === 'open' ? 'bg-green-600' : 
                          port.state === 'closed' ? 'bg-red-600' : 'bg-gray-600'
                        }`}>
                          {port.state}
                        </span>
                        {port.service && (
                          <span className="px-2 py-1 bg-blue-600 text-white text-xs rounded">
                            {port.service}
                          </span>
                        )}
                      </div>
                      <Network className="w-4 h-4 text-blue-400" />
                    </div>

                    <div className="space-y-2">
                      {port.service && (
                        <div className="text-sm text-gray-300">
                          <span className="text-gray-400">Service:</span> {port.service}
                          {port.version && <span className="text-gray-400"> v{port.version}</span>}
                        </div>
                      )}
                      {port.banner && (
                        <div className="text-sm text-gray-300">
                          <span className="text-gray-400">Banner:</span> <code className="bg-gray-900 px-1 rounded">{port.banner}</code>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {selectedTab === 'vulnerabilities' && (
          <div className="space-y-4">
            {allVulnerabilities.length === 0 ? (
              <p className="text-gray-400 text-center py-8">No vulnerabilities found.</p>
            ) : (
              <div className="grid gap-4">
                {allVulnerabilities.map((vuln: any, index: number) => (
                  <div key={`${vuln.name}-${index}`} className={`p-4 rounded border ${getSeverityColor(vuln.severity)}`}>
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h3 className="font-semibold text-white mb-1">{vuln.name}</h3>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                          {vuln.cvss_score && (
                            <span className="text-sm text-gray-400">
                              CVSS: {vuln.cvss_score}
                            </span>
                          )}
                        </div>
                      </div>
                      <AlertTriangle className="w-5 h-5 text-yellow-400" />
                    </div>

                    <p className="text-gray-300 text-sm mb-3">{vuln.description}</p>

                    {vuln.references && vuln.references.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-xs font-medium text-gray-400">References:</span>
                        {vuln.references.map((ref: string, refIndex: number) => (
                          <div key={refIndex} className="text-xs text-blue-400 hover:text-blue-300">
                            <a href={ref} target="_blank" rel="noopener noreferrer">
                              {ref}
                            </a>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {selectedTab === 'details' && (
          <div className="space-y-4">
            {currentHost ? (
              <div className="bg-gray-800 p-6 rounded border border-gray-600">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold text-white flex items-center">
                    <Server className="w-5 h-5 mr-2 text-blue-400" />
                    Host Summary
                  </h3>
                  <span className="text-sm text-gray-400">
                    Last seen: {currentHost.last_seen ? new Date(currentHost.last_seen).toLocaleString() : 'Unknown'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">IP Address</span>
                    <span className="font-mono text-white">{currentHost.ip}</span>
                  </div>
                  
                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Hostname</span>
                    <span className="text-white">{currentHost.hostname || 'Unknown'}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Status</span>
                    <span className={`font-semibold ${currentHost.status === 'up' ? 'text-green-400' : currentHost.status === 'down' ? 'text-red-400' : 'text-yellow-400'}`}>
                      {currentHost.status?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">MAC Address</span>
                    <span className="font-mono text-white">{currentHost.mac_address || 'Unknown'}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Vendor</span>
                    <span className="text-white">{currentHost.vendor || 'Unknown'}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">OS Name</span>
                    <span className="text-white">{currentHost.os_name || 'Unknown'}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">OS Family</span>
                    <span className="text-white">{currentHost.os_family || 'Unknown'}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">OS Accuracy</span>
                    <span className="text-white">
                      {currentHost.os_accuracy ? `${currentHost.os_accuracy}%` : 'Unknown'}
                    </span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Total Ports</span>
                    <span className="text-white font-semibold">{currentHost.port_count || hostPorts.length}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Open Ports</span>
                    <span className="text-green-400 font-semibold">{hostPorts.filter(p => p.state === 'open').length}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Services</span>
                    <span className="text-blue-400 font-semibold">{hostPorts.filter(p => p.service).length}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Vulnerabilities</span>
                    <span className="text-red-400 font-semibold">{currentHost.vulnerability_count || allVulnerabilities.length}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-gray-400 text-center py-8">
                No target selected for details view.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ResultViewer;