import React, { useState, useEffect } from 'react';
import { listen } from '@tauri-apps/api/event';
import { Target, Shield, Activity, Play, Square, Download, Settings, Zap } from 'lucide-react';
import useScanStore from './stores/scanStore';
import useHostStore from './stores/hostStore';
import HostTable from './components/HostTable';
import ScanProgress from './components/ScanProgress';
import ResultViewer from './components/ResultViewer';

// Types for Tauri backend communication
interface ScanRequest {
  target: string;
  scan_type: string;
  options?: Record<string, any>;
}

// Target input component with Tauri integration
const TargetInput = () => {
  const [target, setTarget] = useState('192.168.1.1-50');
  const [scanType, setScanType] = useState('nmap');
  const { isScanning, startScan, stopScan } = useScanStore();

  const handleStartScan = async () => {
    try {
      const scanTarget = {
        id: crypto.randomUUID(),
        ip: target.trim(),
        hostname: undefined,
        ports: [],
        scan_type: scanType as any,
        options: {
          ports: '1-65535',
          timeout: 30
        }
      };

      await startScan(scanTarget);
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

  return (
    <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
      <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
        <Target className="w-5 h-5 text-blue-400" />
        Target Configuration
      </h2>
      
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Target Range
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.1-50 or example.com"
            className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            disabled={isScanning}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Scan Type
          </label>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
            disabled={isScanning}
          >
            <option value="nmap">Nmap Port Scan</option>
            <option value="masscan">Masscan Fast Scan</option>
            <option value="nikto">Nikto Web Scan</option>
            <option value="dirb">Directory Brute Force</option>
          </select>
        </div>
        
        <div className="flex gap-3">
          <button
            onClick={handleStartScan}
            disabled={isScanning || !target.trim()}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white px-4 py-2 rounded flex items-center justify-center gap-2 transition-colors"
          >
            {isScanning ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Start Scan
              </>
            )}
          </button>
          
          {isScanning && (
            <button
              onClick={handleStopScan}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded flex items-center gap-2 transition-colors"
            >
              <Square className="w-4 h-4" />
              Stop
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

// Live log viewer with Tauri event listening
const LogViewer = () => {
  const [logs, setLogs] = useState<Array<{level: string, message: string, timestamp: Date}>>([]);

  useEffect(() => {
    const unlisten = listen('scan-log', (event: any) => {
      setLogs(prev => [...prev.slice(-99), {
        level: event.payload.level,
        message: event.payload.message,
        timestamp: new Date()
      }]);
    });

    return () => {
      unlisten.then(fn => fn());
    };
  }, []);

  const getLogColor = (level: string) => {
    switch(level) {
      case 'error': return 'text-red-400';
      case 'warning': return 'text-yellow-400';
      case 'success': return 'text-green-400';
      default: return 'text-gray-300';
    }
  };

  return (
    <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
      <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
        <Zap className="w-5 h-5 text-purple-400" />
        Live Logs
      </h2>
      
      <div className="bg-black p-4 rounded font-mono text-sm max-h-64 overflow-y-auto">
        {logs.length === 0 ? (
          <p className="text-gray-500">Waiting for scan activity...</p>
        ) : (
          logs.map((log, index) => (
            <div key={index} className={`${getLogColor(log.level)} mb-1`}>
              [{log.timestamp.toLocaleTimeString()}] {log.message}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

// Clean up unused destructuring
const App: React.FC = () => {
  // Remove unused destructuring - just get what we need from stores
  useScanStore();
  useHostStore();

  // Listen for scan progress updates from Tauri
  useEffect(() => {
    const unlisten = listen('scan-progress', (event: any) => {
      // Update scan progress in store
      console.log('Scan progress:', event.payload);
    });

    return () => {
      unlisten.then(fn => fn());
    };
  }, []);

  // Listen for scan results from Tauri
  useEffect(() => {
    const unlisten = listen('scan-result', (event: any) => {
      // Update results in store
      console.log('Scan result:', event.payload);
    });

    return () => {
      unlisten.then(fn => fn());
    };
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold">LEGION2</h1>
              <p className="text-sm text-gray-400">Advanced Penetration Testing Framework</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <button className="p-2 hover:bg-gray-800 rounded transition-colors">
              <Download className="w-5 h-5" />
            </button>
            <button className="p-2 hover:bg-gray-800 rounded transition-colors">
              <Settings className="w-5 h-5" />
            </button>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="p-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <TargetInput />
          <ScanProgress />
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <HostTable />
          <LogViewer />
        </div>

        <div className="mt-6">
          <ResultViewer />
        </div>
      </main>
    </div>
  );
};

export default App;