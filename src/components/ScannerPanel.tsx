/* LEGION2 - A free and open-source penetration testing tool.
   Copyright (c) 2025 NubleX / Igor Dunaev */


import { invoke } from '@tauri-apps/api/core';
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Database,
  Network,
  Server,
  Shield,
  Target,
  Wifi,
  Zap
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import useAppStore from '../stores/appStore';
import useHostStore, { type Host } from '../stores/hostStore';
import HostTable from './HostTable';
import NetworkMap from './NetworkMap';
import ResultViewer from './ResultViewer';
import ScanForm from './ScanForm';

const EnhancedScannerPanel = () => {
  const [activeTab, setActiveTab] = useState<'scanner' | 'topology' | 'hosts-results'>('scanner');
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  const [scanDuration, setScanDuration] = useState(0);
  const { hosts, setHosts } = useHostStore();
  const terminalRef = useRef<HTMLDivElement>(null);

  const {
    scanInProgress,
    liveOutput,
    metrics,
    startScan,
    cancelScan,
    resetScan
  } = useAppStore();
  // Load existing hosts from database on mount
  useEffect(() => {
    const loadExistingHosts = async () => {
      try {
        console.log('Loading existing hosts from database...');
        const existingHosts = await invoke<Host[]>('get_all_hosts');
        console.log('Loaded existing hosts:', existingHosts);
        if (existingHosts && existingHosts.length > 0) {
          setHosts(existingHosts);
          console.log('Host store updated with', existingHosts.length, 'hosts');
        }
      } catch (error) {
        console.error('Failed to load existing hosts:', error);
      }
    };

    loadExistingHosts();
  }, []);

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

  // Auto-scroll terminal to bottom when new output arrives
  useEffect(() => {
    if (terminalRef.current) {
      // Use requestAnimationFrame to ensure DOM updates are complete
      requestAnimationFrame(() => {
        if (terminalRef.current) {
          terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
      });
    }
  }, [liveOutput]);

  // Also scroll when switching to scanner tab during an active scan
  useEffect(() => {
    if (activeTab === 'scanner' && terminalRef.current) {
      requestAnimationFrame(() => {
        if (terminalRef.current) {
          terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
      });
    }
  }, [activeTab]);

  // Hosts are provided by the host store via obs:host events

  // For Live Output, we'll use a simple terminal-like display instead of ToolOutput

  const handleStartScan = useCallback(async (config: any) => {
    try {
      await startScan(config);
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  }, [startScan]);

  const handleCancelScan = useCallback(async () => {
    await cancelScan();
  }, [cancelScan]);

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
    if (hosts.length > 0) return <CheckCircle className="w-5 h-5 text-green-400" />;
    return <Shield className="w-5 h-5 text-blue-400" />;
  };

  const getScanStatusText = () => {
    if (scanInProgress) return 'Scanning...';
    if (hosts.length > 0) return 'Scan Complete - Ready for New Scan';
    return 'Ready to Start';
  };

  return (
    <div className="h-screen w-screen bg-gray-950 flex flex-col">
      {/* Compact Header with All Statistics */}
      <div className="flex-shrink-0 bg-gray-800 border-b border-gray-700">
        <div className="px-4 py-2">
          <div className="flex items-center justify-between">
            {/* Logo and Title */}
            <div className="flex items-center space-x-3">
              <Shield className="w-6 h-6 text-blue-400" />
              <h1 className="text-lg font-bold text-white">LEGION2</h1>
            </div>

            {/* Comprehensive Statistics */}
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Server className="w-4 h-4 text-green-400" />
                <span className="text-sm text-white font-medium">{hosts.length}</span>
                <span className="text-xs text-gray-400">hosts</span>
              </div>

              <div className="flex items-center space-x-2">
                <Wifi className="w-4 h-4 text-blue-400" />
                <span className="text-sm text-white font-medium">{metrics.services_discovered}</span>
                <span className="text-xs text-gray-400">services</span>
              </div>

              <div className="flex items-center space-x-2">
                <Network className="w-4 h-4 text-purple-400" />
                <span className="text-sm text-white font-medium">
                  {hosts.reduce((total, host) => total + (host.port_count || 0), 0)}
                </span>
                <span className="text-xs text-gray-400">ports</span>
              </div>

              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                <span className="text-sm text-white font-medium">
                  {hosts.reduce((total, host) => total + (host.vulnerability_count || 0), 0)}
                </span>
                <span className="text-xs text-gray-400">vulns</span>
              </div>

              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-blue-400" />
                <span className="text-sm text-white font-medium">{metrics.processing_rate.toFixed(1)}/s</span>
                <span className="text-xs text-gray-400">rate</span>
              </div>

              {/* Status */}
              <div className="flex items-center space-x-2">
                {getScanStatusIcon()}
                <span className="text-sm font-medium text-white">
                  {getScanStatusText()}
                </span>
              </div>

              {/* Duration */}
              {scanInProgress && (
                <div className="flex items-center space-x-2">
                  <Clock className="w-4 h-4 text-blue-400" />
                  <span className="text-sm text-white font-mono">
                    {formatDuration(scanDuration)}
                  </span>
                </div>
              )}

              {/* Ready for New Scan Button */}
              {!scanInProgress && hosts.length > 0 && (
                <button
                  onClick={() => {
                    setActiveTab('scanner');
                    resetScan();
                  }}
                  className="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-sm rounded transition-colors flex items-center gap-1"
                >
                  <Target className="w-3 h-3" />
                  Ready for New Scan
                </button>
              )}
            </div>
          </div>

          {/* Progress Bar (when scanning) */}
          {scanInProgress && (
            <div className="mt-2">
              <div className="bg-gray-700 rounded-full h-1">
                <div className="bg-blue-500 h-1 rounded-full animate-pulse" style={{ width: '100%' }} />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex-shrink-0 bg-gray-900 border-b border-gray-700">
        <div className="flex space-x-1 p-2">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`px-4 py-2 rounded-md transition-all duration-200 flex items-center space-x-2 ${activeTab === 'scanner'
              ? 'bg-blue-600 text-white shadow-lg'
              : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
          >
            <Zap className="w-4 h-4" />
            <span>Scanner</span>
          </button>
          <button
            onClick={() => setActiveTab('topology')}
            className={`px-4 py-2 rounded-md transition-all duration-200 flex items-center space-x-2 ${activeTab === 'topology'
              ? 'bg-blue-600 text-white shadow-lg'
              : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
          >
            <Wifi className="w-4 h-4" />
            <span>Network Topology</span>
          </button>
          <button
            onClick={() => setActiveTab('hosts-results')}
            className={`px-4 py-2 rounded-md transition-all duration-200 flex items-center space-x-2 ${activeTab === 'hosts-results'
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

      {/* Main Content Area */}
      <div className="flex-1 flex overflow-hidden min-h-0">
        {activeTab === 'scanner' ? (
          /* Scanner Tab Layout */
          <div className="flex-1 flex">
            {/* Left Panel - Enhanced Scan Controls */}
            <div className="w-1/2 min-w-0 border-r border-gray-700 flex flex-col bg-gray-800">
              <div className="p-4 border-b border-gray-700">
                <h2 className="text-lg font-semibold text-white flex items-center">
                  <Target className="w-5 h-5 mr-2 text-blue-400" />
                  Scan Configuration
                </h2>
              </div>
              <div className="flex-1 p-4 overflow-y-auto">
                <ScanForm
                  onStartScan={handleStartScan}
                  onCancelScan={handleCancelScan}
                  isScanning={scanInProgress}
                  className="h-full"
                />
              </div>
            </div>

            {/* Right Panel - Enhanced Terminal Output */}
            <div className="w-1/2 min-w-0 flex flex-col bg-black">
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
                <div ref={terminalRef} className="h-full bg-black p-4 font-mono text-sm overflow-y-auto scroll-smooth">
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
        ) : activeTab === 'topology' ? (
          /* Network Topology Tab - Full Screen */
          <div className="flex-1 flex flex-col bg-gray-900">
            <div className="flex-1 overflow-hidden">
              <NetworkMap
                hosts={hosts}
                onHostSelect={handleHostSelect}
                selectedHostIp={selectedHost?.ip}
                className="h-full w-full"
              />
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
                  {selectedHost ? `Target Information - ${selectedHost.ip}` : 'Target Information'}
                </h2>
                {selectedHost && (
                  <div className="flex items-center space-x-4 mt-2">
                    <span className="text-sm text-gray-400">
                      {selectedHost.hostname || 'No hostname'}
                    </span>
                    <span className={`text-xs px-2 py-1 rounded ${selectedHost.status === 'up' ? 'bg-green-600' : 'bg-red-600'
                      } text-white`}>
                      {selectedHost.status?.toUpperCase()}
                    </span>
                  </div>
                )}
              </div>
              <div className="flex-1 overflow-y-auto">
                {selectedHost ? (
                  <ResultViewer selectedHost={selectedHost} />
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