// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import React, { useState } from 'react';
import { AlertTriangle, ExternalLink, RefreshCw, X } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import type { ServiceInfo, CveInfo, ServiceEnrichment } from '../types/services';

interface ServiceEnrichmentProps {
  service: ServiceInfo;
  hostIp: string;
  onClose: () => void;
}

const ServiceEnrichment: React.FC<ServiceEnrichmentProps> = ({ service, hostIp, onClose }) => {
  const [enriching, setEnriching] = useState(false);
  const [enrichmentData, setEnrichmentData] = useState<ServiceEnrichment | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleEnrich = async () => {
    setEnriching(true);
    setError(null);
    try {
      const result = await invoke<string>('enrich_service_osint', {
        hostIp,
        port: service.port,
        serviceName: service.name,
        version: service.version,
      });
      
      // For now, just show a message since OSINT is not yet implemented
      // When OSINT module is ready, this will return actual enrichment data
      setEnrichmentData({
        service,
        cves: [],
        enriched_at: new Date().toISOString(),
        source: 'osint',
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to enrich service');
    } finally {
      setEnriching(false);
    }
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

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-900 rounded-lg border border-gray-700 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-white">Service Enrichment</h2>
            <p className="text-sm text-gray-400">
              {service.name} on {hostIp}:{service.port}/{service.protocol}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Service Info */}
          <div className="bg-gray-800 p-4 rounded border border-gray-700">
            <h3 className="text-sm font-semibold text-gray-400 mb-2">Service Information</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-400">Name:</span>
                <span className="ml-2 text-white">{service.name}</span>
              </div>
              <div>
                <span className="text-gray-400">Port:</span>
                <span className="ml-2 text-white font-mono">{service.port}/{service.protocol}</span>
              </div>
              <div>
                <span className="text-gray-400">State:</span>
                <span className={`ml-2 px-2 py-1 rounded text-xs ${
                  service.state === 'open' ? 'bg-green-600' : 'bg-gray-600'
                }`}>
                  {service.state}
                </span>
              </div>
              {service.version && (
                <div>
                  <span className="text-gray-400">Version:</span>
                  <span className="ml-2 text-white">{service.version}</span>
                </div>
              )}
            </div>
            {service.banner && (
              <div className="mt-4">
                <span className="text-gray-400 text-sm">Banner:</span>
                <code className="block mt-1 bg-gray-900 px-2 py-1 rounded text-xs text-gray-300">
                  {service.banner}
                </code>
              </div>
            )}
          </div>

          {/* CVEs */}
          <div className="bg-gray-800 p-4 rounded border border-gray-700">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-400">CVEs ({service.cve_count})</h3>
              {service.cve_count > 0 && (
                <a
                  href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXXX`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 text-xs flex items-center gap-1"
                >
                  View on CVE Database
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
            {service.cve_count === 0 ? (
              <p className="text-gray-500 text-sm">No CVEs found for this service.</p>
            ) : (
              <div className="space-y-2">
                <p className="text-gray-400 text-xs">
                  CVE details will be displayed here when available.
                </p>
              </div>
            )}
          </div>

          {/* OSINT Enrichment */}
          <div className="bg-gray-800 p-4 rounded border border-gray-700">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-400">OSINT Enrichment</h3>
              <button
                onClick={handleEnrich}
                disabled={enriching}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-sm rounded flex items-center gap-2"
              >
                {enriching ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Enriching...
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-4 h-4" />
                    Enrich with OSINT
                  </>
                )}
              </button>
            </div>

            {error && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-sm">
                {error}
              </div>
            )}

            {enrichmentData ? (
              <div className="space-y-4">
                <div className="text-sm text-gray-400">
                  Enriched at: {new Date(enrichmentData.enriched_at || '').toLocaleString()}
                </div>
                {enrichmentData.osint_data && (
                  <div>
                    <h4 className="text-xs font-semibold text-gray-400 mb-2">OSINT Data</h4>
                    <pre className="bg-gray-900 p-3 rounded text-xs text-gray-300 overflow-x-auto">
                      {JSON.stringify(enrichmentData.osint_data, null, 2)}
                    </pre>
                  </div>
                )}
                {!enrichmentData.osint_data && (
                  <p className="text-gray-500 text-sm">
                    OSINT enrichment is not yet implemented. This feature will be available when the OSINT module is ready.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">
                Click "Enrich with OSINT" to fetch additional intelligence about this service.
              </p>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-700 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default ServiceEnrichment;

