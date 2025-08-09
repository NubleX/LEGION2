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

import React, { useState, useEffect } from 'react';
import { Activity, Clock, Target, Shield, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { useLegionStore } from '../stores/legionStore';
import { scanAPI } from '../services/tauriApi';
import type { ScanResult, ScanStatistics } from '../types/scanning';

interface ScanProgressProps {
  showDetails?: boolean;
  onScanComplete?: (results: any) => void;
  onError?: (error: string) => void;
}

// Define backend API types that might differ from your main types
interface BackendScanProgress {
  scan_id: string;
  progress: number;
  current_phase: string;
  discovered_hosts: number;
  total_ports_scanned: number;
  open_ports_found: number;
  estimated_time_remaining?: number;
  message?: string;
  start_time: string;
  current_target?: string;
  hosts_discovered?: number; // Alternative naming
  ports_found?: number;      // Alternative naming
  vulnerabilities?: number;
  estimated_remaining?: number;
}

interface BackendScanStatistics {
  total_scans: number;
  active_scans: number;
  completed_scans?: number;
  failed_scans?: number;
  total_hosts_discovered?: number;
  total_ports_found?: number;
  total_vulnerabilities?: number;
  hosts_discovered?: number;        // Alternative naming
  vulnerabilities_found?: number;   // Alternative naming
}

const ScanProgress: React.FC<ScanProgressProps> = ({ 
  showDetails = true, 
  onScanComplete: _onScanComplete, 
  onError 
}) => {
  // Your existing store data (always available)
  const {
    isScanning: storeIsScanning,
    activeScans: storeActiveScans,
    currentProgress: storeProgress,
    statistics: storeStatistics,
    cancelScan: storeCancelScan,
    cancelAllScans: storeCancelAllScans
  } = useLegionStore();

  // Backend data (may not be available initially)
  const [backendProgress, setBackendProgress] = useState<Map<string, BackendScanProgress>>(new Map());
  const [backendStats, setBackendStats] = useState<BackendScanStatistics | null>(null);
  const [isBackendScanning, setIsBackendScanning] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [expandedScans, setExpandedScans] = useState<Set<string>>(new Set());

  // Smart Fallback System Implementation
  const getEffectiveData = () => {
    // 1. Try Backend Data First
    if (backendProgress.size > 0 || backendStats) {
      console.log('🔄 Using BACKEND data (real-time from Tauri API)');
      return {
        activeScans: Array.from(backendProgress.values()).map(progress => ({
          id: progress.scan_id,
          target_id: progress.current_target || 'Unknown',
          status: progress.progress === 100 ? 'completed' : 
                  progress.current_phase === 'Failed' ? 'failed' :
                  progress.current_phase === 'Cancelled' ? 'cancelled' : 'running',
          start_time: progress.start_time,
          scan_type: 'network',
          open_ports: [],
          vulnerabilities: [],
          error_message: progress.current_phase === 'Failed' ? progress.message : undefined
        } as ScanResult)),
        progress: backendProgress,
        statistics: backendStats || storeStatistics,
        isScanning: isBackendScanning
      };
    }
    
    // 2. Fallback to Store Data
    if (storeActiveScans.size > 0) {
      console.log('📦 Using STORE data (fallback from useScanStore)');
      return {
        activeScans: Array.from(storeActiveScans.values()),
        progress: storeProgress,
        statistics: storeStatistics,
        isScanning: storeIsScanning
      };
    }
    
    // 3. Safe Defaults
    console.log('🔧 Using DEFAULT data (safe fallbacks)');
    return {
      activeScans: [],
      progress: new Map(),
      statistics: {
        total_scans: 0,
        active_scans: 0,
        total_hosts_discovered: 0,
        total_vulnerabilities: 0
      } as ScanStatistics,
      isScanning: false
    };
  };

  // Poll backend for real data
  useEffect(() => {
    let intervalId: NodeJS.Timeout;

    const fetchBackendData = async () => {
      try {
        // Try to get real scan progress
        if (scanAPI?.getScanProgress) {
          const progress = await scanAPI.getScanProgress();
          const progressMap = new Map();
          progress.forEach((scan: any) => {
            progressMap.set(scan.scan_id, scan as BackendScanProgress);
          });
          setBackendProgress(progressMap);
        }

        // Try to check if actually scanning
        if (scanAPI?.isScanning) {
          const scanning = await scanAPI.isScanning();
          setIsBackendScanning(scanning);
        }

        // Try to get real statistics
        if (scanAPI?.getScanStatistics) {
          const stats = await scanAPI.getScanStatistics();
          setBackendStats(stats as BackendScanStatistics);
        }

        // Clear errors on success
        setBackendError(null);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Backend connection failed';
        setBackendError(errorMessage);
        console.warn('⚠️ Backend unavailable, using fallback data:', errorMessage);
        
        if (onError) {
          onError(errorMessage);
        }
      }
    };

    // Initial fetch
    fetchBackendData();

    // Poll every 2 seconds
    intervalId = setInterval(fetchBackendData, 2000);

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [onError]);

  // Note: Event listening is now handled by ScannerPanel to avoid duplication
  // This component focuses on progress display only

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

  // Enhanced cancel functions that try backend first, then store
  const cancelScan = async (scanId: string) => {
    try {
      // Try backend first
      if (scanAPI?.cancelNetworkScan) {
        await scanAPI.cancelNetworkScan(scanId);
      }
      // Also update store as fallback
      storeCancelScan(scanId);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to cancel scan';
      setBackendError(errorMessage);
      // Try store cancellation as backup
      storeCancelScan(scanId);
      
      if (onError) {
        onError(errorMessage);
      }
    }
  };

  const cancelAllScans = async () => {
    try {
      // Try backend first
      if (scanAPI?.cancelNetworkScan) {
        const promises = Array.from(backendProgress.keys()).map(scanId => 
          scanAPI.cancelNetworkScan(scanId)
        );
        await Promise.all(promises);
      }
      setBackendProgress(new Map());
      setIsBackendScanning(false);
      
      // Also update store
      storeCancelAllScans();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to cancel scans';
      setBackendError(errorMessage);
      // Try store cancellation as backup
      storeCancelAllScans();
      
      if (onError) {
        onError(errorMessage);
      }
    }
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

  // Get effective data using smart fallback system
  const { activeScans, progress, statistics, isScanning } = getEffectiveData();

  return (
    <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold text-white flex items-center gap-2">
          <Activity className="w-5 h-5 text-green-400" />
          Scan Progress
          {/* Data Source Indicator */}
          <span className="text-xs px-2 py-1 rounded bg-gray-700 text-gray-300">
            {backendProgress.size > 0 ? '🔄 Live' : '📦 Store'}
          </span>
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

      {/* Error Display */}
      {backendError && (
        <div className="mb-4 p-3 bg-yellow-900/50 border border-yellow-700 rounded">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            <span className="text-yellow-300 text-sm">
              Backend offline - using cached data: {backendError}
            </span>
          </div>
        </div>
      )}

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-blue-400">{statistics.active_scans}</div>
          <div className="text-sm text-gray-400">Active</div>
        </div>
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-green-400">
            {(statistics as BackendScanStatistics).completed_scans || 0}
          </div>
          <div className="text-sm text-gray-400">Completed</div>
        </div>
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-yellow-400">
            {statistics.total_hosts_discovered || 
             (statistics as BackendScanStatistics).hosts_discovered || 0}
          </div>
          <div className="text-sm text-gray-400">Hosts Found</div>
        </div>
        <div className="bg-gray-800 p-3 rounded">
          <div className="text-2xl font-bold text-red-400">
            {statistics.total_vulnerabilities || 
             (statistics as BackendScanStatistics).vulnerabilities_found || 0}
          </div>
          <div className="text-sm text-gray-400">Vulnerabilities</div>
        </div>
      </div>

      {/* Active Scans */}
      {activeScans.length === 0 ? (
        <div className="text-center py-8 text-gray-400">
          <Target className="w-12 h-12 mx-auto mb-2 opacity-50" />
          <p>No active scans. Start a scan to see progress here.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {activeScans.map((scan: ScanResult) => {
            // Get progress data - try backend first, then store
            const backendProgressData = backendProgress.get(scan.id);
            const storeProgressData = progress.get(scan.id);
            const effectiveProgress = backendProgressData || storeProgressData;
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
                    {effectiveProgress && (
                      <div className="text-right">
                        <div className="text-sm font-medium text-white">
                          {Math.round(effectiveProgress.progress)}%
                        </div>
                        <div className="text-xs text-gray-400">
                          {effectiveProgress.current_phase || 'Processing...'}
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
                {effectiveProgress && (
                  <div className="mt-3">
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-300 ${
                          scan.status === 'completed' ? 'bg-green-500' :
                          scan.status === 'failed' ? 'bg-red-500' :
                          'bg-blue-500'
                        }`}
                        style={{ width: `${effectiveProgress.progress}%` }}
                      />
                    </div>
                    {effectiveProgress.estimated_time_remaining && effectiveProgress.estimated_time_remaining > 0 && (
                      <div className="text-xs text-gray-400 mt-1">
                        Est. {Math.round(effectiveProgress.estimated_time_remaining / 60)}m remaining
                      </div>
                    )}
                    {effectiveProgress.estimated_remaining && effectiveProgress.estimated_remaining > 0 && (
                      <div className="text-xs text-gray-400 mt-1">
                        Est. {Math.round(effectiveProgress.estimated_remaining / 60)}m remaining
                      </div>
                    )}
                  </div>
                )}

                {/* Detailed Progress */}
                {showDetails && isExpanded && effectiveProgress && (
                  <div className="mt-4 pt-4 border-t border-gray-700">
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-gray-400">Hosts Discovered:</span>
                        <span className="ml-2 text-white">
                          {effectiveProgress.discovered_hosts || 
                           effectiveProgress.hosts_discovered || 0}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Ports Scanned:</span>
                        <span className="ml-2 text-white">
                          {effectiveProgress.total_ports_scanned || 0}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-400">Open Ports:</span>
                        <span className="ml-2 text-green-400">
                          {effectiveProgress.open_ports_found || 
                           effectiveProgress.ports_found || 0}
                        </span>
                      </div>
                    </div>
                    
                    {effectiveProgress.message && (
                      <div className="mt-3 p-2 bg-gray-700 rounded">
                        <span className="text-sm text-gray-300">{effectiveProgress.message}</span>
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