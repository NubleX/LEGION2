// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { AlertTriangle, ChevronDown, ChevronRight, Download, ExternalLink, Network, RefreshCw, Server, Shield } from 'lucide-react';
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import useHostStore, { type Host, selectVisibleHosts } from '../stores/hostStore';
import useServiceStore from '../stores/serviceStore';
import ServiceTable from './ServiceTable';

interface PortInfo {
  number: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
  banner?: string;
}

interface VulnerabilityInfo {
  id: string;
  host_ip: string;
  name: string;
  severity: string;
  description: string;
  cve_id?: string;
  cvss_score?: number;
  discovered_at: string;
  last_seen: string;
  references?: string[];
}

interface CveDetail {
  name: string;
  product: string;
  version: string;
  url: string;
  source: string;
  severity: string;
  description: string;
  cvss_score?: number;
  published_date?: string;
  last_modified_date?: string;
  references: string[];
  cwe: string[];
  is_exploitable: boolean;
  risk_score: number;
}

interface ServiceStatisticsInfo {
  total_services: number;
  vulnerable_services: number;
  web_services: number;
  database_services: number;
  average_risk_score: number;
}

interface ResultViewerProps {
  selectedScanId?: string;
  selectedHost?: Host;
  className?: string;
}


/**
 * Compares two port arrays to determine if they are different.
 * Returns true if ports have changed, false if identical.
 */
function portsChanged(oldPorts: PortInfo[], newPorts: PortInfo[]): boolean {
  if (oldPorts.length !== newPorts.length) return true;
  
  // Create a map for quick comparison
  const oldPortsMap = new Map(oldPorts.map(p => [`${p.number}/${p.protocol}`, p]));
  
  for (const newPort of newPorts) {
    const key = `${newPort.number}/${newPort.protocol}`;
    const oldPort = oldPortsMap.get(key);
    
    if (!oldPort) return true; // New port found
    
    // Compare critical fields
    if (oldPort.state !== newPort.state ||
        oldPort.service !== newPort.service ||
        oldPort.version !== newPort.version ||
        oldPort.banner !== newPort.banner) {
      return true;
    }
  }
  
  return false;
}

/**
 * Compares two vulnerability arrays to determine if they are different.
 * Returns true if vulnerabilities have changed, false if identical.
 */
function vulnerabilitiesChanged(oldVulns: VulnerabilityInfo[], newVulns: VulnerabilityInfo[]): boolean {
  if (oldVulns.length !== newVulns.length) return true;
  
  // Create a map for quick comparison
  const oldVulnsMap = new Map(oldVulns.map(v => [v.id || v.name, v]));
  
  for (const newVuln of newVulns) {
    const key = newVuln.id || newVuln.name;
    const oldVuln = oldVulnsMap.get(key);
    
    if (!oldVuln) return true; // New vulnerability found
    
    // Compare critical fields
    if (oldVuln.severity !== newVuln.severity ||
        oldVuln.cvss_score !== newVuln.cvss_score ||
        oldVuln.last_seen !== newVuln.last_seen) {
      return true;
    }
  }
  
  return false;
}

const ResultViewer: React.FC<ResultViewerProps> = ({ selectedScanId, selectedHost }) => {
  // Only subscribe to hosts array, memoize the current host lookup
  const hosts = useHostStore(selectVisibleHosts);
  
  const [selectedTab, setSelectedTab] = useState<'ports' | 'services' | 'vulnerabilities' | 'details'>('ports');
  const loadServices = useServiceStore((state) => state.loadServices);
  const [hostPorts, setHostPorts] = useState<PortInfo[]>([]);
  const [loadingPorts, setLoadingPorts] = useState(false);
  const [hostVulnerabilities, setHostVulnerabilities] = useState<VulnerabilityInfo[]>([]);
  const [loadingVulnerabilities, setLoadingVulnerabilities] = useState(false);
  const [scanningVulnerabilities, setScanningVulnerabilities] = useState(false);
  const [vulnScanMessage, setVulnScanMessage] = useState<string | null>(null);
  const [expandedVulnIds, setExpandedVulnIds] = useState<Set<string>>(new Set());
  const [cveDetails, setCveDetails] = useState<Record<string, CveDetail>>({});
  const [fetchingCveIds, setFetchingCveIds] = useState<Set<string>>(new Set());
  const [serviceStats, setServiceStats] = useState<ServiceStatisticsInfo | null>(null);

  // Get the host either from selectedHost prop or by selectedScanId (treating it as host ID)
  // Memoize to avoid recalculating on every render
  const currentHost = useMemo(() => {
    return selectedHost || (selectedScanId ? hosts.find(h => h.id === selectedScanId) : null);
  }, [selectedHost, selectedScanId, hosts]);

  const loadVulnerabilities = useCallback((ip: string) => {
    setLoadingVulnerabilities(true);
    invoke<VulnerabilityInfo[]>('get_host_vulnerabilities', { hostIp: ip })
      .then(vulns => {
        setHostVulnerabilities(prevVulns => {
          if (!vulnerabilitiesChanged(prevVulns, vulns)) {
            return prevVulns;
          }
          return vulns;
        });
      })
      .catch(err => {
        console.error('Failed to load vulnerabilities:', err);
        setHostVulnerabilities([]);
      })
      .finally(() => setLoadingVulnerabilities(false));
  }, []);

  const loadServiceStats = useCallback((ip: string) => {
    invoke<ServiceStatisticsInfo>('get_service_statistics', { hostIp: ip })
      .then(setServiceStats)
      .catch(err => {
        console.error('Failed to load service statistics:', err);
        setServiceStats(null);
      });
  }, []);

  const runVulnerabilityScan = useCallback(async (ip: string) => {
    setScanningVulnerabilities(true);
    setVulnScanMessage(null);
    try {
      const ports = await invoke<PortInfo[]>('get_host_ports_detailed', { hostIp: ip });
      if (ports.length === 0) {
        setVulnScanMessage('No ports in database for this host. Run a service scan (nmap phase) first.');
        return;
      }

      const result = await invoke<{
        vulnerabilities_found: number;
        analysis_time_ms: number;
      }>('analyze_host_vulnerabilities', {
        request: { host_ip: ip, force_rescan: true },
      });
      loadVulnerabilities(ip);
      loadServiceStats(ip);
      setVulnScanMessage(
        result.vulnerabilities_found > 0
          ? `Found ${result.vulnerabilities_found} potential vulnerabilities.`
          : `Scan complete: no known vulnerabilities matched ${ports.length} open port(s).`
      );
    } catch (err) {
      console.error('Vulnerability scan failed:', err);
      setVulnScanMessage('Vulnerability scan failed. Check backend logs for details.');
    } finally {
      setScanningVulnerabilities(false);
    }
  }, [loadVulnerabilities, loadServiceStats]);

  const fetchCveDetails = useCallback(async (cveId: string) => {
    setFetchingCveIds(prev => new Set(prev).add(cveId));
    try {
      const detail = await invoke<CveDetail>('fetch_cve', { cveId });
      setCveDetails(prev => ({ ...prev, [cveId]: detail }));
    } catch (err) {
      console.error(`Failed to fetch CVE ${cveId}:`, err);
    } finally {
      setFetchingCveIds(prev => {
        const next = new Set(prev);
        next.delete(cveId);
        return next;
      });
    }
  }, []);

  const toggleVulnExpanded = useCallback((id: string) => {
    setExpandedVulnIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const loadPorts = useCallback((ip: string) => {
    console.log('[ResultViewer] Loading ports for host:', ip);
    setLoadingPorts(true);
    invoke<PortInfo[]>('get_host_ports_detailed', { hostIp: ip })
      .then(ports => {
        console.log(`[ResultViewer] Successfully loaded ${ports.length} ports for host ${ip}:`, ports);
        // Only update state if ports have actually changed
        setHostPorts(prevPorts => {
          if (!portsChanged(prevPorts, ports)) {
            console.log('[ResultViewer] Ports unchanged, skipping state update');
            return prevPorts;
          }
          return ports;
        });
        if (ports.length === 0) {
          console.warn(`[ResultViewer] No ports found for host ${ip} - this may indicate a database issue or the host has no ports`);
        }
      })
      .catch(err => {
        console.error(`[ResultViewer] Failed to load ports for host ${ip}:`, err);
        setHostPorts([]);
      })
      .finally(() => setLoadingPorts(false));
  }, []);

  // Load ports and services when host changes
  useEffect(() => {
    if (currentHost?.ip) {
      loadPorts(currentHost.ip);
      loadServices(currentHost.ip).catch(console.error);
    } else {
      setHostPorts([]);
    }
  }, [currentHost?.ip, loadServices]);

  // Refresh ports when notified of updates for the selected host
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      unlisten = await listen<string>('refresh_host_ports', (event) => {
        if (currentHost?.ip && event.payload === currentHost.ip) {
          console.log('[ResultViewer] Received refresh_host_ports event for', currentHost.ip);
          loadPorts(currentHost.ip);
        }
      });
    })();
    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, [currentHost?.ip]);

  // Periodic refresh to fetch updated data from DB (every 27 seconds while a host is selected)
  useEffect(() => {
    if (!currentHost?.ip) {
      return;
    }

    const hostIp = currentHost.ip;
    console.log('[ResultViewer] Starting periodic refresh for host', hostIp);
    const intervalId = setInterval(() => {
      console.log('[ResultViewer] Periodic refresh: fetching ports for', hostIp);
      loadPorts(hostIp);
    }, 27000); // Refresh every 27 seconds

    return () => {
      console.log('[ResultViewer] Stopping periodic refresh for host', hostIp);
      clearInterval(intervalId);
    };
  }, [currentHost?.ip, loadPorts]);

  // Load vulnerabilities and service stats when host changes
  useEffect(() => {
    if (currentHost?.ip) {
      loadVulnerabilities(currentHost.ip);
      loadServiceStats(currentHost.ip);
    } else {
      setHostVulnerabilities([]);
      setServiceStats(null);
    }
  }, [currentHost?.ip, loadVulnerabilities, loadServiceStats]);

  const allVulnerabilities = hostVulnerabilities;

  const allPorts = useMemo(() => {
    if (!hostPorts) return [];
    return hostPorts;
  }, [hostPorts]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
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
      {/* Compact Header with Tabs and Export */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          {/* Tabs */}
          <div className="flex space-x-1 bg-gray-800 rounded-lg p-1">
            {(['ports', 'services', 'vulnerabilities', 'details'] as const).map((tab) => (
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
          
          <button
            onClick={exportResults}
            className="flex items-center gap-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="p-6">


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

        {selectedTab === 'services' && (
          <div className="space-y-4">
            {currentHost?.ip ? (
              <ServiceTable
                hostIp={currentHost.ip}
                onServiceSelect={(service) => {
                  console.log('Service selected:', service);
                }}
              />
            ) : (
              <p className="text-gray-400 text-center py-8">No host selected.</p>
            )}
          </div>
        )}

        {selectedTab === 'vulnerabilities' && (
          <div className="space-y-4">
            {currentHost?.ip && (
              <div className="flex flex-wrap items-center justify-between gap-3">
                {serviceStats && (
                  <div className="flex flex-wrap gap-3 text-xs text-gray-400">
                    <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700">
                      {serviceStats.total_services} services
                    </span>
                    <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700 text-orange-400">
                      {serviceStats.vulnerable_services} vulnerable
                    </span>
                    <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700 text-blue-400">
                      {serviceStats.web_services} web
                    </span>
                    <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700 text-purple-400">
                      {serviceStats.database_services} database
                    </span>
                    <span className="px-2 py-1 bg-gray-800 rounded border border-gray-700">
                      avg risk {serviceStats.average_risk_score.toFixed(1)}
                    </span>
                  </div>
                )}
                <button
                  onClick={() => currentHost.ip && runVulnerabilityScan(currentHost.ip)}
                  disabled={scanningVulnerabilities}
                  className="flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white text-sm rounded transition-colors ml-auto"
                >
                  <RefreshCw className={`w-4 h-4 ${scanningVulnerabilities ? 'animate-spin' : ''}`} />
                  {scanningVulnerabilities ? 'Scanning...' : 'Run Vulnerability Scan'}
                </button>
              </div>
            )}

            {vulnScanMessage && (
              <p className="text-sm text-gray-300 bg-gray-800 border border-gray-700 rounded px-3 py-2">
                {vulnScanMessage}
              </p>
            )}

            {loadingVulnerabilities ? (
              <p className="text-gray-400 text-center py-8">Loading vulnerabilities...</p>
            ) : allVulnerabilities.length === 0 ? (
              <div className="text-center py-8 space-y-3">
                <p className="text-gray-400">No vulnerabilities found.</p>
                {currentHost?.ip && (
                  <button
                    onClick={() => runVulnerabilityScan(currentHost.ip)}
                    disabled={scanningVulnerabilities}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white text-sm rounded transition-colors"
                  >
                    Run Vulnerability Scan
                  </button>
                )}
              </div>
            ) : (
              <div className="grid gap-4">
                {allVulnerabilities.map((vuln: VulnerabilityInfo, index: number) => {
                  const vulnKey = vuln.id || `${vuln.name}-${index}`;
                  const isExpanded = expandedVulnIds.has(vulnKey);
                  const cveDetail = vuln.cve_id ? cveDetails[vuln.cve_id] : undefined;
                  const references = cveDetail?.references?.length
                    ? cveDetail.references
                    : vuln.references || [];
                  const description = cveDetail?.description || vuln.description;
                  const cvssScore = cveDetail?.cvss_score ?? vuln.cvss_score;

                  return (
                    <div key={vulnKey} className={`rounded border ${getSeverityColor(vuln.severity)}`}>
                      <button
                        type="button"
                        onClick={() => toggleVulnExpanded(vulnKey)}
                        className="w-full p-4 text-left"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-2 min-w-0">
                            {isExpanded ? (
                              <ChevronDown className="w-4 h-4 text-gray-400 mt-1 flex-shrink-0" />
                            ) : (
                              <ChevronRight className="w-4 h-4 text-gray-400 mt-1 flex-shrink-0" />
                            )}
                            <div className="min-w-0">
                              <h3 className="font-semibold text-white mb-1">{vuln.name}</h3>
                              <div className="flex flex-wrap items-center gap-2">
                                <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(vuln.severity)}`}>
                                  {vuln.severity.toUpperCase()}
                                </span>
                                {cvssScore != null && (
                                  <span className="text-sm text-gray-400">CVSS: {cvssScore}</span>
                                )}
                                {vuln.cve_id && (
                                  <span className="text-sm text-blue-400">{vuln.cve_id}</span>
                                )}
                              </div>
                            </div>
                          </div>
                          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0" />
                        </div>
                      </button>

                      {isExpanded && (
                        <div className="px-4 pb-4 border-t border-gray-700/50 pt-3 space-y-3">
                          <p className="text-gray-300 text-sm">{description}</p>

                          {vuln.cve_id && (
                            <div className="flex flex-wrap items-center gap-2">
                              <button
                                type="button"
                                onClick={() => fetchCveDetails(vuln.cve_id!)}
                                disabled={fetchingCveIds.has(vuln.cve_id)}
                                className="flex items-center gap-1 px-2 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-blue-400 text-xs rounded border border-gray-600"
                              >
                                <ExternalLink className="w-3 h-3" />
                                {fetchingCveIds.has(vuln.cve_id) ? 'Fetching from NVD...' : 'Fetch from NVD'}
                              </button>
                              {cveDetail?.url && (
                                <a
                                  href={cveDetail.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-xs text-blue-400 hover:text-blue-300"
                                >
                                  View on NVD
                                </a>
                              )}
                            </div>
                          )}

                          {cveDetail && (
                            <div className="grid grid-cols-2 gap-2 text-xs text-gray-400">
                              {cveDetail.published_date && (
                                <span>Published: {new Date(cveDetail.published_date).toLocaleDateString()}</span>
                              )}
                              {cveDetail.cwe.length > 0 && (
                                <span>CWE: {cveDetail.cwe.join(', ')}</span>
                              )}
                              {cveDetail.is_exploitable && (
                                <span className="text-red-400">Exploit available</span>
                              )}
                              <span>Risk score: {cveDetail.risk_score.toFixed(1)}</span>
                            </div>
                          )}

                          {references.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs font-medium text-gray-400">References:</span>
                              {references.map((ref: string, refIndex: number) => (
                                <div key={refIndex} className="text-xs text-blue-400 hover:text-blue-300">
                                  <a href={ref} target="_blank" rel="noopener noreferrer">
                                    {ref}
                                  </a>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
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
                    <span className="text-gray-400">Vendor</span>
                    <span className="text-white">{currentHost.vendor || 'Unknown'}</span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">Status</span>
                    <span className={`font-semibold ${currentHost.status === 'up' ? 'text-green-400' : currentHost.status === 'down' ? 'text-red-400' : 'text-yellow-400'}`}>
                      {currentHost.status ? currentHost.status.toUpperCase() : 'UNKNOWN'}
                    </span>
                  </div>

                  <div className="flex justify-between py-2 border-b border-gray-700">
                    <span className="text-gray-400">MAC Address</span>
                    <span className="font-mono text-white">{currentHost.mac_address || 'Unknown'}</span>
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
                    <span className="text-white font-semibold">{currentHost.port_count ?? hostPorts.length}</span>
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
                    <span className="text-red-400 font-semibold">{currentHost.vulnerability_count ?? allVulnerabilities.length}</span>
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