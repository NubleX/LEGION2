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


import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import useAppStore from '../stores/appStore';
import type { Host } from '../stores/hostStore';
import ScanForm from './ScanForm';
import NetworkMap from './NetworkMap';
import HostTable from './HostTable';
import ResultViewer from './ResultViewer';
import { 
  Shield, 
  Activity, 
  Clock, 
  Database,
  Zap,
  Server,
  CheckCircle,
  Wifi,
  Target
} from 'lucide-react';

const EnhancedScannerPanel = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'hosts-results'>('dashboard');
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  const [scanDuration, setScanDuration] = useState(0);
  const hosts = useHostStore(state => state.hosts);
  
  const {
    scanInProgress,
    liveOutput,
    metrics,
    startScan
  } = useAppStore();
  // Simple scan duration tracking
  useEffect(() => {
    let interval: NodeJS.Timeout;
    let startTime = Date.now();
    
    if (scanInProgress) {
      interval = setInterval(() => {
        setScanDuration(Math.floor((Date.now() - startTime) / 1000));
      }, 1000);
    } else {
      setScanDuration(0);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [scanInProgress]);

  // Hosts are provided by the host store via obs:host events

  // For Live Output, we'll use a simple terminal-like display instead of ToolOutput

  const handleStartScan = useCallback(async (config: any) => {
    try {
      await startScan(config);
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  }, [startScan]);

  const handleHostSelect = useCallback((host: Host) => {
    setSelectedHost(host);
  }, []);

  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getScanStatusIcon = () => {
    if (scanInProgress) return <Activity className="w-5 h-5 text-yellow-400 animate-pulse" />;
    if (metrics.hosts_discovered > 0) return <CheckCircle className="w-5 h-5 text-green-400" />;
    return <Shield className="w-5 h-5 text-blue-400" />;
  };

  const getScanStatusText = () => {
    if (scanInProgress) return 'Scanning...';
    if (metrics.hosts_discovered > 0) return 'Scan Complete';
    return 'Ready';
  };

  return (
    <div className="h-screen w-screen bg-gray-950 flex flex-col">
      {/* Enhanced Header with Real-time Stats */}
      <div className="flex-shrink-0 bg-gray-800 border-b border-gray-700">
        <div className="p-4">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-blue-400" />
              <div>
                <h1 className="text-xl font-bold text-white">LEGION2</h1>
                <p className="text-sm text-gray-400">Advanced Network Scanner</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-6">
              {/* Real-time Status */}
              <div className="flex items-center space-x-2">
                {getScanStatusIcon()}
                <span className="text-sm font-medium text-white">
                  {getScanStatusText()}
                </span>
              </div>
              
              {/* Scan Duration */}
              {scanInProgress && (
                <div className="flex items-center space-x-2">
                  <Clock className="w-4 h-4 text-blue-400" />
                  <span className="text-sm text-white font-mono">
                    {formatDuration(scanDuration)}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Real-time Statistics Bar */}
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="bg-gray-700 rounded-lg p-3 flex items-center space-x-3">
              <Server className="w-5 h-5 text-green-400" />
              <div>
                <div className="text-lg font-bold text-white">{metrics.hosts_discovered}</div>
                <div className="text-xs text-gray-400">Hosts Discovered</div>
              </div>
            </div>
            <div className="bg-gray-700 rounded-lg p-3 flex items-center space-x-3">
              <Wifi className="w-5 h-5 text-blue-400" />
              <div>
                <div className="text-lg font-bold text-white">{metrics.services_discovered}</div>
                <div className="text-xs text-gray-400">Services Found</div>
              </div>
            </div>
            <div className="bg-gray-700 rounded-lg p-3 flex items-center space-x-3">
              <Activity className="w-5 h-5 text-blue-400" />
              <div>
                <div className="text-lg font-bold text-white">{metrics.processing_rate.toFixed(1)}/s</div>
                <div className="text-xs text-gray-400">Processing Rate</div>
              </div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex space-x-1 bg-gray-900 rounded-lg p-1">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-4 py-2 rounded-md transition-all duration-200 flex items-center space-x-2 ${
                activeTab === 'dashboard'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              <Zap className="w-4 h-4" />
              <span>Scanner Dashboard</span>
            </button>
            <button
              onClick={() => setActiveTab('hosts-results')}
              className={`px-4 py-2 rounded-md transition-all duration-200 flex items-center space-x-2 ${
                activeTab === 'hosts-results'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              <Database className="w-4 h-4" />
              <span>Hosts & Results</span>
              {hosts && hosts.length > 0 && (
                <span className="bg-blue-500 text-white text-xs px-2 py-0.5 rounded-full">
                  {hosts.length}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Simple Progress Indicator (when scanning) */}
        {scanInProgress && (
          <div className="px-4 pb-4">
            <div className="bg-gray-700 rounded-full h-2">
              <div 
                className="bg-blue-500 h-2 rounded-full transition-all duration-500"
                style={{ width: '100%' }}
              >
                <div className="h-full bg-gradient-to-r from-blue-500 to-blue-400 rounded-full animate-pulse" />
              </div>
            </div>
            <div className="text-xs text-gray-400 mt-1">
              Processing rate: {metrics.processing_rate.toFixed(1)} obs/sec
            </div>
          </div>
        )}
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex overflow-hidden min-h-0">
        {activeTab === 'dashboard' ? (
          /* Enhanced Dashboard Layout */
          <div className="flex-1 flex">
            {/* Left Panel - Enhanced Scan Controls */}
            <div className="w-1/3 min-w-0 border-r border-gray-700 flex flex-col bg-gray-800">
              <div className="p-4 border-b border-gray-700">
                <h2 className="text-lg font-semibold text-white flex items-center">
                  <Target className="w-5 h-5 mr-2 text-blue-400" />
                  Scan Configuration
                </h2>
              </div>
              <div className="flex-1 p-4 overflow-y-auto">
                <ScanForm 
                  onStartScan={handleStartScan}
                  isScanning={scanInProgress}
                  className="h-full"
                />
              </div>
            </div>

            {/* Center Panel - Enhanced Network Map */}
            <div className="w-1/3 min-w-0 border-r border-gray-700 flex flex-col bg-gray-900">
              <div className="p-4 border-b border-gray-700">
                <h2 className="text-lg font-semibold text-white flex items-center">
                  <Wifi className="w-5 h-5 mr-2 text-green-400" />
                  Network Topology
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  {metrics.hosts_discovered} hosts discovered
                </p>
              </div>
              <div className="flex-1 p-4 overflow-hidden">
                <NetworkMap
                  hosts={hosts}
                  onHostSelect={handleHostSelect}
                  selectedHostIp={selectedHost?.ip}
                  className="h-full w-full"
                />
              </div>
            </div>

            {/* Right Panel - Enhanced Terminal Output */}
            <div className="w-1/3 min-w-0 flex flex-col bg-black">
              <div className="p-4 border-b border-gray-700 bg-gray-900">
                <h2 className="text-lg font-semibold text-white flex items-center">
                  <Activity className="w-5 h-5 mr-2 text-green-400" />
                  Live Output
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  Real-time scan results and tool output
                </p>
              </div>
              <div className="flex-1 overflow-hidden">
                {/* Terminal-like Live Output */}
                <div className="h-full bg-black p-4 font-mono text-sm overflow-y-auto">
                  {liveOutput.length === 0 ? (
                    <div className="text-gray-500 text-center mt-8">
                      No scan output yet. Start a scan to see live results.
                    </div>
                  ) : (
                    <div className="space-y-1">
                      {liveOutput.map((line, index) => (
                        <div key={index} className="text-green-400 whitespace-pre-wrap">
                          {line}
                        </div>
                      ))}
                      {scanInProgress && (
                        <div className="text-yellow-400 animate-pulse">
                          <span className="inline-block w-2 h-4 bg-yellow-400 ml-1"></span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* Enhanced Hosts & Results Layout */
          <div className="flex-1 flex">
            {/* Left Panel - Enhanced Host Table */}
            <div className="w-1/2 min-w-0 border-r border-gray-700 flex flex-col bg-gray-800">
              <div className="p-4 border-b border-gray-700">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-semibold text-white flex items-center">
                    <Server className="w-5 h-5 mr-2 text-blue-400" />
                    Discovered Hosts
                  </h2>
                  <div className="flex items-center space-x-4">
                    <span className="text-sm text-gray-400">
                      {hosts.length} hosts
                    </span>
                    {selectedHost && (
                      <span className="text-xs bg-blue-600 px-2 py-1 rounded text-white">
                        Selected: {selectedHost.ip}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto">
                <HostTable onHostSelect={handleHostSelect} />
              </div>
            </div>

            {/* Right Panel - Enhanced Results Viewer */}
            <div className="w-1/2 min-w-0 flex flex-col bg-gray-900">
              <div className="p-4 border-b border-gray-700">
                <h2 className="text-lg font-semibold text-white flex items-center">
                  <Database className="w-5 h-5 mr-2 text-green-400" />
                  {selectedHost ? `Results for ${selectedHost.ip}` : 'Host Details'}
                </h2>
                {selectedHost && (
                  <div className="flex items-center space-x-4 mt-2">
                    <span className="text-sm text-gray-400">
                      {selectedHost.hostname || 'No hostname'}
                    </span>
                    <span className={`text-xs px-2 py-1 rounded ${
                      selectedHost.status === 'up' ? 'bg-green-600' : 'bg-red-600'
                    } text-white`}>
                      {selectedHost.status?.toUpperCase()}
                    </span>
                  </div>
                )}
              </div>
              <div className="flex-1 overflow-y-auto">
                {selectedHost ? (
                  <ResultViewer selectedScanId={selectedHost.id} />
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-400">
                    <div className="text-center">
                      <Server className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p className="text-lg mb-2">No Host Selected</p>
                      <p className="text-sm">Select a host from the list to view detailed results</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EnhancedScannerPanel;