import React, { useEffect, useState } from 'react';
import { Activity, Clock, Target, Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import useScanStore from '../stores/scanStore';
import type { ScanResult, ScanProgress as ScanProgressType } from '../types/scanning';

interface ScanProgressProps {
  showDetails?: boolean;
}

const ScanProgress: React.FC<ScanProgressProps> = ({ showDetails = true }) => {
  const {
    activeScans,
    currentProgress,
    statistics,
    isScanning,
    cancelScan,
    cancelAllScans
  } = useScanStore();

  const [expandedScans, setExpandedScans] = useState<Set<string>>(new Set());

  const toggleScanExpansion = (scanId: string) => {
    setExpandedScans(prev => {
      const newSet = new Set(prev);
      if (newSet.has(scanId)) {
        newSet.delete(scanId);
      } else {
        newSet.add(scanId);
      }
      return newSet;
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'text-blue-400';
      case 'completed': return 'text-green-400';
      case 'failed': return 'text-red-400';
      case 'cancelled': return 'text-gray-400';
      default: return 'text-yellow-400';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <Activity className="w-4 h-4 animate-spin" />;
      case 'completed': return <CheckCircle className="w-4 h-4" />;
      case 'failed': return <XCircle className="w-4 h-4" />;
      case 'cancelled': return <XCircle className="w-4 h-4" />;
      default: return <Clock className="w-4 h-4" />;
    }
  };

  const formatDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const diff = end.getTime() - start.getTime();
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  const activeScanArray = Array.from(activeScans.values());

  return (
    <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold text-white flex items-center gap-2">
          <Activity className="w-5 h-5 text-green-400" />
          Scan Progress
        </h2>
        
        {isScanning && (
          <button
            onClick={cancelAllScans}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded transition-colors"
          >
            Cancel All
          </button>
        )}
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-blue-400">{statistics.active_scans}</div>
          <div className="text-sm text-gray-400">Active</div>
        </div>
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-green-400">{statistics.completed_scans}</div>
          <div className="text-sm text-gray-400">Completed</div>
        </div>
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-yellow-400">{statistics.total_hosts_discovered}</div>
          <div className="text-sm text-gray-400">Hosts Found</div>
        </div>
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-red-400">{statistics.total_vulnerabilities}</div>
          <div className="text-sm text-gray-400">Vulnerabilities</div>
        </div>
      </div>

      {/* Active Scans */}
      {activeScanArray.length === 0 ? (
        <div className="text-center py-8 text-gray-400">
          <Target className="w-12 h-12 mx-auto mb-2 opacity-50" />
          <p>No active scans. Start a scan to see progress here.</p>
        </div>
      ) : (
        <div className="space-y-4">
                      {activeScanArray.map((scan: ScanResult) => {
            const progress = currentProgress.get(scan.id);
            const isExpanded = expandedScans.has(scan.id);
            
            return (
              <div key={scan.id} className="bg-gray-800 p-4 rounded border border-gray-600">
                {/* Scan Header */}
                <div 
                  className="flex items-center justify-between cursor-pointer"
                  onClick={() => showDetails && toggleScanExpansion(scan.id)}
                >
                  <div className="flex items-center gap-3">
                    <span className={getStatusColor(scan.status)}>
                      {getStatusIcon(scan.status)}
                    </span>
                    <div>
                      <h3 className="font-semibold text-white">
                        {scan.scan_type.toUpperCase()} - {scan.target_id}
                      </h3>
                      <p className="text-sm text-gray-400">
                        Started {formatDuration(scan.start_time)} ago
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    {progress && (
                      <div className="text-right">
                        <div className="text-sm font-medium text-white">
                          {progress.progress}%
                        </div>
                        <div className="text-xs text-gray-400">
                          {progress.current_phase}
                        </div>
                      </div>
                    )}
                    
                    {scan.status === 'running' && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          cancelScan(scan.id);
                        }}
                        className="px-2 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
                      >
                        Cancel
                      </button>
                    )}
                  </div>
                </div>

                {/* Progress Bar */}
                {progress && (
                  <div className="mt-3">
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-300 ${
                          scan.status === 'completed' ? 'bg-green-500' :
                          scan.status === 'failed' ? 'bg-red-500' :
                          'bg-blue-500'
                        }`}
                        style={{ width: `${progress.progress}%` }}
                      />
                    </div>
                    {progress.estimated_time_remaining && (
                      <div className="text-xs text-gray-400 mt-1">
                        Est. {Math.round(progress.estimated_time_remaining / 60)}m remaining
                      </div>
                    )}
                  </div>
                )}

                {/* Detailed Progress */}
                {showDetails && isExpanded && progress && (
                  <div className="mt-4 pt-4 border-t border-gray-700">
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-gray-400">Hosts Discovered:</span>
                        <span className="ml-2 text-white">{progress.discovered_hosts}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Ports Scanned:</span>
                        <span className="ml-2 text-white">{progress.total_ports_scanned}</span>
                      </div>
                      <div>
                        <span className="text-gray-400">Open Ports:</span>
                        <span className="ml-2 text-green-400">{progress.open_ports_found}</span>
                      </div>
                    </div>
                    
                    {progress.message && (
                      <div className="mt-3 p-2 bg-gray-700 rounded">
                        <span className="text-sm text-gray-300">{progress.message}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Error Message */}
                {scan.error_message && (
                  <div className="mt-3 p-3 bg-red-900/20 border border-red-500/30 rounded">
                    <div className="flex items-center gap-2 text-red-400">
                      <AlertTriangle className="w-4 h-4" />
                      <span className="text-sm">{scan.error_message}</span>
                    </div>
                  </div>
                )}

                {/* Results Summary */}
                {scan.status === 'completed' && scan.open_ports.length > 0 && (
                  <div className="mt-3 p-3 bg-green-900/20 border border-green-500/30 rounded">
                    <div className="flex items-center gap-2 text-green-400 mb-2">
                      <Shield className="w-4 h-4" />
                      <span className="text-sm font-medium">Scan Complete</span>
                    </div>
                    <div className="text-xs text-gray-300">
                      Found {scan.open_ports.length} open ports
                      {scan.vulnerabilities.length > 0 && 
                        `, ${scan.vulnerabilities.length} vulnerabilities`
                      }
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default ScanProgress;