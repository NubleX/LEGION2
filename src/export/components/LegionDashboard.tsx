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
import { Target, Shield, AlertTriangle, Play, Square, Database } from 'lucide-react';
import { useLegionStore } from '../stores/legionStore';

export const LegionDashboard: React.FC = () => {
  const [targetIp, setTargetIp] = useState('');
  const [scanType, setScanType] = useState('Quick');
  
  const {
    startScan,
    cancelScan,
    isScanning,
    activeScanIds,
    scanProgress,
    statistics,
    hosts,
    vulnerabilities,
    refreshStatistics,
    refreshHosts,
    refreshVulnerabilities,
  } = useLegionStore();

  useEffect(() => {
    // Load initial data
    refreshStatistics();
    refreshHosts();
    refreshVulnerabilities();
  }, []);

  const handleStartScan = async () => {
    if (!targetIp.trim()) {
      alert('Please enter a target IP address');
      return;
    }

    try {
      await startScan(targetIp.trim(), scanType);
    } catch (error) {
      alert(`Failed to start scan: ${error}`);
    }
  };

  const handleCancelAllScans = async () => {
    try {
      await Promise.all(Array.from(activeScanIds).map(scanId => cancelScan(scanId)));
    } catch (error) {
      alert(`Failed to cancel scans: ${error}`);
    }
  };

  const getProgressForScan = (scanId: string) => scanProgress.get(scanId) || 0;

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="text-blue-600" size={32} />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">LEGION2</h1>
                <p className="text-gray-600">Advanced Penetration Testing Framework</p>
              </div>
            </div>
            
            {statistics && (
              <div className="grid grid-cols-4 gap-4 text-center">
                <div>
                  <div className="text-2xl font-bold text-blue-600">{statistics.total_scans}</div>
                  <div className="text-sm text-gray-600">Total Scans</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-green-600">{statistics.hosts_discovered}</div>
                  <div className="text-sm text-gray-600">Hosts Found</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-orange-600">{statistics.vulnerabilities_found}</div>
                  <div className="text-sm text-gray-600">Vulnerabilities</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-red-600">{statistics.active_scans}</div>
                  <div className="text-sm text-gray-600">Active Scans</div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Scan Control */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Target className="text-blue-600" size={24} />
            <h2 className="text-xl font-bold">Network Scanner</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium mb-1">Target IP/Range</label>
              <input
                type="text"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                placeholder="192.168.1.1 or 192.168.1.0/24"
                className="w-full px-3 py-2 border rounded focus:ring-2 focus:ring-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Scan Type</label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full px-3 py-2 border rounded focus:ring-2 focus:ring-blue-500"
              >
                <option value="Quick">Quick Scan</option>
                <option value="Comprehensive">Comprehensive Scan</option>
                <option value="Stealth">Stealth Scan</option>
              </select>
            </div>

            <div className="flex items-end">
              <button
                onClick={handleStartScan}
                disabled={isScanning}
                className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 mr-2"
              >
                <Play size={16} />
                Start Scan
              </button>

              {isScanning && (
                <button
                  onClick={handleCancelAllScans}
                  className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
                >
                  <Square size={16} />
                  Cancel All
                </button>
              )}
            </div>
          </div>

          {/* Active Scans */}
          {activeScanIds.size > 0 && (
            <div className="mt-4">
              <h3 className="font-medium mb-2">Active Scans:</h3>
              {Array.from(activeScanIds).map(scanId => {
                const progress = getProgressForScan(scanId);
                return (
                  <div key={scanId} className="flex items-center justify-between bg-gray-50 p-3 rounded mb-2">
                    <span className="text-sm font-medium">Scan {scanId.slice(0, 8)}...</span>
                    <div className="flex items-center gap-3">
                      <div className="w-32 bg-gray-200 rounded-full h-2">
                        <div 
                          className="bg-blue-600 h-2 rounded-full transition-all"
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                      <span className="text-xs w-12">{Math.round(progress)}%</span>
                      <button
                        onClick={() => cancelScan(scanId)}
                        className="text-red-600 hover:text-red-800"
                      >
                        <Square size={16} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Results Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Discovered Hosts */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center gap-2 mb-4">
              <Database className="text-green-600" size={24} />
              <h2 className="text-xl font-bold">Discovered Hosts</h2>
            </div>
            
            <div className="max-h-96 overflow-y-auto">
              {hosts.length === 0 ? (
                <p className="text-gray-500 text-center py-8">No hosts discovered yet</p>
              ) : (
                hosts.map(host => (
                  <div key={host.id} className="border-b pb-2 mb-2 last:border-b-0">
                    <div className="flex justify-between items-center">
                      <div>
                        <div className="font-medium">{host.ip}</div>
                        {host.hostname && <div className="text-sm text-gray-600">{host.hostname}</div>}
                      </div>
                      <span className={`px-2 py-1 text-xs rounded ${
                        host.status === 'up' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                      }`}>
                        {host.status}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Vulnerabilities */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="text-red-600" size={24} />
              <h2 className="text-xl font-bold">Vulnerabilities</h2>
            </div>
            
            <div className="max-h-96 overflow-y-auto">
              {vulnerabilities.length === 0 ? (
                <p className="text-gray-500 text-center py-8">No vulnerabilities found</p>
              ) : (
                vulnerabilities.map(vuln => (
                  <div key={vuln.id} className="border-b pb-2 mb-2 last:border-b-0">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="font-medium">{vuln.name}</div>
                        <div className="text-sm text-gray-600">{vuln.description}</div>
                      </div>
                      <span className={`px-2 py-1 text-xs rounded ml-2 ${
                        vuln.severity === 'Critical' ? 'bg-red-100 text-red-800' :
                        vuln.severity === 'High' ? 'bg-orange-100 text-orange-800' :
                        vuln.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {vuln.severity}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};