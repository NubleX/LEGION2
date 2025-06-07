import React, { useState, useMemo } from 'react';
import { Shield, AlertTriangle, Download, Search } from 'lucide-react';
import useScanStore from '../stores/scanStore';
import type { Vulnerability, Port } from '../types/scanning';

interface ResultViewerProps {
  selectedScanId?: string;
}

const ResultViewer: React.FC<ResultViewerProps> = ({ selectedScanId }) => {
  const { scanHistory, getScanById } = useScanStore();
  
  const [selectedTab, setSelectedTab] = useState<'ports' | 'vulnerabilities' | 'details'>('ports');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');

  const currentScan = selectedScanId ? getScanById(selectedScanId) : null;
  const results = currentScan ? [currentScan] : scanHistory.filter(scan => scan.status === 'completed');

  const allVulnerabilities = useMemo(() => {
    const vulns = results.flatMap(scan => scan.vulnerabilities);
    return vulns.filter(vuln => {
      if (severityFilter !== 'all' && vuln.severity !== severityFilter) return false;
      if (searchTerm && !vuln.name.toLowerCase().includes(searchTerm.toLowerCase())) return false;
      return true;
    });
  }, [results, severityFilter, searchTerm]);

  const allPorts = useMemo(() => {
    const ports = results.flatMap(scan => scan.open_ports);
    return ports.filter(port => {
      if (searchTerm) {
        const searchLower = searchTerm.toLowerCase();
        return port.service?.toLowerCase().includes(searchLower) || 
               port.number.toString().includes(searchTerm);
      }
      return true;
    });
  }, [results, searchTerm]);

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
      scan_results: results,
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

  if (results.length === 0) {
    return (
      <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
        <div className="text-center py-8 text-gray-400">
          <Shield className="w-12 h-12 mx-auto mb-2 opacity-50" />
          <p>No scan results available. Complete a scan to see results here.</p>
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
            Scan Results
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
              className={`px-4 py-2 rounded transition-colors capitalize ${
                selectedTab === tab
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
            {allPorts.length === 0 ? (
              <p className="text-gray-400 text-center py-8">No open ports found.</p>
            ) : (
              <div className="grid gap-4">
                {allPorts.map((port, index) => (
                  <div key={`${port.number}-${port.protocol}-${index}`} className="bg-gray-800 p-4 rounded border border-gray-600">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <span className="text-lg font-mono text-white">
                          {port.number}/{port.protocol}
                        </span>
                        <span className={`font-medium ${getPortStateColor(port.state)}`}>
                          {port.state}
                        </span>
                        {port.service && (
                          <span className="px-2 py-1 bg-blue-600 text-white text-xs rounded">
                            {port.service}
                          </span>
                        )}
                      </div>
                      {port.confidence && (
                        <span className="text-sm text-gray-400">
                          {port.confidence}% confidence
                        </span>
                      )}
                    </div>

                    {port.version && (
                      <div className="text-sm text-gray-300 mb-2">
                        Version: {port.version}
                      </div>
                    )}

                    {port.banner && (
                      <div className="bg-gray-900 p-2 rounded font-mono text-xs text-gray-300">
                        {port.banner}
                      </div>
                    )}
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
                {allVulnerabilities.map((vuln, index) => (
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
                        {vuln.references.map((ref, refIndex) => (
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
          <div className="space-y-6">
            {results.map((scan) => (
              <div key={scan.id} className="bg-gray-800 p-4 rounded border border-gray-600">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-white">
                    {scan.scan_type.toUpperCase()} Scan
                  </h3>
                  <span className="text-sm text-gray-400">
                    {scan.end_time && new Date(scan.end_time).toLocaleString()}
                  </span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="bg-gray-900 p-3 rounded">
                    <div className="text-sm text-gray-400">Target</div>
                    <div className="font-mono text-white">{scan.target_id}</div>
                  </div>
                  <div className="bg-gray-900 p-3 rounded">
                    <div className="text-sm text-gray-400">Duration</div>
                    <div className="text-white">
                      {scan.end_time ? 
                        `${Math.round((new Date(scan.end_time).getTime() - new Date(scan.start_time).getTime()) / 1000)}s` :
                        'In progress'
                      }
                    </div>
                  </div>
                  <div className="bg-gray-900 p-3 rounded">
                    <div className="text-sm text-gray-400">Open Ports</div>
                    <div className="text-green-400 font-semibold">{scan.open_ports.length}</div>
                  </div>
                  <div className="bg-gray-900 p-3 rounded">
                    <div className="text-sm text-gray-400">Vulnerabilities</div>
                    <div className="text-red-400 font-semibold">{scan.vulnerabilities.length}</div>
                  </div>
                </div>

                {scan.error_message && (
                  <div className="bg-red-900/20 border border-red-500/30 p-3 rounded mb-4">
                    <div className="flex items-center gap-2 text-red-400">
                      <AlertTriangle className="w-4 h-4" />
                      <span className="text-sm">{scan.error_message}</span>
                    </div>
                  </div>
                )}

                {scan.raw_output && (
                  <details className="mt-4">
                    <summary className="cursor-pointer text-sm text-gray-400 hover:text-white">
                      Show Raw Output
                    </summary>
                    <div className="mt-2 bg-gray-900 p-3 rounded font-mono text-xs text-gray-300 overflow-x-auto">
                      <pre>{scan.raw_output}</pre>
                    </div>
                  </details>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ResultViewer;