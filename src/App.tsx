// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

// Forked from an earlier version of LEGION, which was originally created by Gotham Security.
// It was archived in 2024 and Kali Linux users were left with a broken program.

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

import React, { useEffect, useState } from 'react';
import { Target, Shield, Activity, Play, Square, AlertCircle } from 'lucide-react';

// Add global type for window.__TAURI__
declare global {
  interface Window {
    __TAURI__?: any;
  }
}

// Types
interface ScanTarget {
  ip: string;
  hostname?: string;
  ports: number[];
  scan_type: 'Quick' | 'Comprehensive' | 'Stealth';
}

// Simple component that uses window.__TAURI__ directly
export default function SimpleScanApp() {
  const [target, setTarget] = useState('127.0.0.1');
  const [scanType, setScanType] = useState<'Quick' | 'Comprehensive' | 'Stealth'>('Quick');
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Helper to check if Tauri is available
  const tauriAvailable = () => {
    return typeof window !== 'undefined' && window.__TAURI__ && window.__TAURI__.invoke;
  };

  // Helper to call Tauri commands
  const callTauri = async (cmd: string, args?: any) => {
    if (!tauriAvailable()) {
      throw new Error('Tauri API not available');
    }
    return window.__TAURI__.invoke(cmd, args);
  };

  // Helper to listen to Tauri events
  useEffect(() => {
    if (!tauriAvailable()) {
      setError('Tauri API not available. Make sure you are running inside Tauri.');
      return;
    }

    // Listen for scan progress events
    const setupListeners = async () => {
      try {
        // Use window.__TAURI__.event.listen if available
        if (window.__TAURI__.event && window.__TAURI__.event.listen) {
          const unlisten1 = await window.__TAURI__.event.listen('scan-progress', (event: any) => {
            addLog(`Progress: ${JSON.stringify(event.payload)}`);
          });

          const unlisten2 = await window.__TAURI__.event.listen('scan-result', (event: any) => {
            addLog(`Result received: ${JSON.stringify(event.payload)}`);
            setIsScanning(false);
          });

          // Cleanup
          return () => {
            unlisten1();
            unlisten2();
          };
        }
      } catch (err) {
        console.error('Failed to setup event listeners:', err);
      }
    };

    setupListeners();
  }, []);

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [`[${timestamp}] ${message}`, ...prev].slice(0, 50));
  };

  const handleStartScan = async () => {
    try {
      setError(null);
      setIsScanning(true);
      
      const scanTarget: ScanTarget = {
        ip: target,
        hostname: undefined,
        ports: [],
        scan_type: scanType,
      };

      addLog(`Starting ${scanType} scan on ${target}`);
      
      const scanId = await callTauri('start_scan', { target: scanTarget });
      addLog(`Scan started with ID: ${scanId}`);

    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg);
      addLog(`Error: ${errorMsg}`);
      setIsScanning(false);
    }
  };

  const handleTestConnection = async () => {
    try {
      addLog('Testing Tauri connection...');
      const hosts = await callTauri('get_hosts');
      addLog(`Connected! Found ${hosts.length} hosts in database.`);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog(`Connection test failed: ${errorMsg}`);
      setError(errorMsg);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white p-6">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-400" />
            LEGION2 Scanner
          </h1>
          <p className="text-gray-400 mt-2">Simple Nmap Integration Test</p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-6 p-4 bg-red-900/20 border border-red-500 rounded-lg flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-red-500" />
            <span className="text-red-400">{error}</span>
            <button 
              onClick={() => setError(null)}
              className="ml-auto text-red-400 hover:text-red-300"
            >
              ✕
            </button>
          </div>
        )}

        {/* Main Controls */}
        <div className="bg-gray-900 p-6 rounded-lg border border-gray-700 mb-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-blue-400" />
            Scan Configuration
          </h2>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target IP
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="127.0.0.1"
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white"
                disabled={isScanning}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan Type
              </label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value as any)}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white"
                disabled={isScanning}
              >
                <option value="Quick">Quick Scan</option>
                <option value="Comprehensive">Comprehensive</option>
                <option value="Stealth">Stealth</option>
              </select>
            </div>

            <div className="flex gap-3">
              <button
                onClick={handleStartScan}
                disabled={isScanning}
                className={`flex-1 py-2 px-4 rounded font-medium flex items-center justify-center gap-2 ${
                  isScanning 
                    ? 'bg-gray-700 text-gray-400 cursor-not-allowed' 
                    : 'bg-blue-600 hover:bg-blue-700 text-white'
                }`}
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

              <button
                onClick={handleTestConnection}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded font-medium"
              >
                Test Connection
              </button>
            </div>
          </div>
        </div>

        {/* Activity Log */}
        <div className="bg-gray-900 p-6 rounded-lg border border-gray-700">
          <h2 className="text-xl font-semibold mb-4">Activity Log</h2>
          
          <div className="h-64 overflow-y-auto font-mono text-sm space-y-1 bg-gray-950 p-3 rounded">
            {logs.length === 0 ? (
              <p className="text-gray-500">No activity yet. Click "Test Connection" to verify Tauri is working.</p>
            ) : (
              logs.map((log, index) => (
                <div key={index} className="text-gray-300">
                  {log}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Debug Info */}
        <div className="mt-4 text-xs text-gray-500">
          Tauri Available: {tauriAvailable() ? '✅ Yes' : '❌ No'}
        </div>
      </div>
    </div>
  );
}