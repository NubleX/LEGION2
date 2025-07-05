import { useState } from 'react';
import { useLegionStore } from '../stores/legionStore';
import useHostStore, { Host } from '../stores/hostStore';
import ScanForm from './ScanForm';
import ToolOutput from './ToolOutput';
import NetworkMap from './NetworkMap';
import HostTable from './HostTable';
import ResultViewer from './ResultViewer';

const ScannerPanel = () => {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'hosts-results'>('dashboard');
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  
  const {
    currentScan,
    isScanning,
    verboseOutput,
    vulnerabilities,
    startScan,
    stopScan
  } = useLegionStore();

  const { hosts } = useHostStore();

  // Convert verboseOutput to ToolOutput format with terminal styling
  const toolOutputs = verboseOutput.map((line, index) => ({
    id: index.toString(),
    tool: line.includes('nmap') ? 'nmap' : line.includes('masscan') ? 'masscan' : 'system',
    command: line.includes('nmap') || line.includes('masscan') ? line : 'Processing...',
    timestamp: new Date().toISOString(),
    stdout: line,
    stderr: '',
    exitCode: 0,
    duration: 0,
    isRunning: isScanning
  }));

  const handleStartScan = async (config: any) => {
    try {
      await startScan(config.targets, config.scanType);
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  };

  const handleStopScan = async () => {
    try {
      await stopScan();
    } catch (error) {
      console.error('Failed to stop scan:', error);
    }
  };

  const handleHostSelect = (host: Host) => {
    setSelectedHost(host);
  };

  return (
    <div className="h-screen w-screen bg-gray-950 flex flex-col">
      {/* Header */}
      <div className="flex-shrink-0 p-4 border-b border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">LEGION2</h1>
            <p className="text-gray-400 text-sm">Network Penetration Testing Tool</p>
          </div>
          
          {/* Tab Toggle */}
          <div className="flex space-x-1 bg-gray-800 rounded-lg p-1">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-4 py-2 rounded transition-colors ${
                activeTab === 'dashboard'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              🚀 Dashboard
            </button>
            <button
              onClick={() => setActiveTab('hosts-results')}
              className={`px-4 py-2 rounded transition-colors ${
                activeTab === 'hosts-results'
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-700'
              }`}
            >
              📊 Hosts & Results ({hosts.length})
            </button>
          </div>
        </div>

        {/* Quick Progress Bar (always visible when scanning) */}
        {currentScan && isScanning && (
          <div className="mt-4 bg-gray-900 border border-gray-700 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                Scanning {currentScan.targetIp} ({currentScan.scanType})
              </span>
              <button
                onClick={handleStopScan}
                className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded transition-colors"
              >
                Cancel
              </button>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${currentScan.progress}%` }}
              />
            </div>
            <div className="text-xs text-gray-400 mt-1">
              {currentScan.progress.toFixed(1)}% complete
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden min-h-0">
        {activeTab === 'dashboard' ? (
          /* Dashboard Layout: Scanner | Map | Output */
          <>
            {/* Left Panel - Scanner */}
            <div className="w-1/3 min-w-0 border-r border-gray-700 flex flex-col">
              <div className="flex-1 p-4 overflow-y-auto">
                <ScanForm 
                  onStartScan={handleStartScan}
                  isScanning={isScanning}
                />
              </div>
            </div>

            {/* Center Panel - Network Map */}
            <div className="w-1/3 min-w-0 border-r border-gray-700 flex flex-col">
              <div className="flex-1 p-4 overflow-hidden">
                <NetworkMap 
                  hosts={hosts || []}
                  onHostSelect={handleHostSelect}
                  selectedHostId={selectedHost?.id}
                />
              </div>
            </div>

            {/* Right Panel - Terminal Output */}
            <div className="w-1/3 min-w-0 flex flex-col">
              <div className="flex-1 p-4 overflow-hidden">
                <div className="h-full bg-black rounded-lg border border-gray-700 flex flex-col">
                  {/* Terminal Header */}
                  <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700 bg-gray-900 rounded-t-lg flex-shrink-0">
                    <div className="flex items-center gap-2">
                      <div className="flex gap-1">
                        <div className="w-3 h-3 rounded-full bg-red-500"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500"></div>
                      </div>
                      <span className="text-sm text-gray-400 font-mono">
                        legion2@terminal
                      </span>
                    </div>
                    <span className="text-xs text-gray-500">
                      {verboseOutput.length} lines
                    </span>
                  </div>

                  {/* Terminal Content */}
                  <div className="flex-1 p-4 overflow-y-auto font-mono text-sm min-h-0">
                    {verboseOutput.length === 0 ? (
                      <div className="text-green-400 opacity-60">
                        <div>LEGION2 v2.0.0 - Network Security Scanner</div>
                        <div className="mt-2">Waiting for scan to start...</div>
                        <div className="mt-1 animate-pulse">█</div>
                      </div>
                    ) : (
                      <div className="space-y-1">
                        {verboseOutput.map((line, index) => (
                          <div key={index} className="text-green-400 whitespace-pre-wrap break-all">
                            <span className="text-gray-600 mr-2">
                              {String(index + 1).padStart(3, '0')}
                            </span>
                            {line}
                          </div>
                        ))}
                        {isScanning && (
                          <div className="text-green-400 animate-pulse mt-2">█</div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </>
        ) : (
          /* Hosts & Results Tab */
          <div className="flex-1 flex min-h-0">
            {/* Left Panel - Hosts */}
            <div className="w-1/2 min-w-0 border-r border-gray-700 p-4 overflow-y-auto">
              <HostTable 
                onHostSelect={handleHostSelect}
                showActions={true}
              />
            </div>

            {/* Right Panel - Results */}
            <div className="w-1/2 min-w-0 p-4 overflow-y-auto">
              <ResultViewer 
                selectedScanId={selectedHost?.id}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScannerPanel;