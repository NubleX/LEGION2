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

import { AlertCircle, Network, Play, Settings, Shield, Target, Zap, Square } from 'lucide-react';
import React, { useState } from 'react';
import { ScanConfig } from '../types/scanning';

interface ScanFormProps {
  onStartScan: (config: ScanConfig) => Promise<void>;
  onCancelScan?: () => Promise<void>;
  isScanning: boolean;
  className?: string;
}

const ScanForm: React.FC<ScanFormProps> = ({ onStartScan, onCancelScan, isScanning }) => {
  const [config, setConfig] = useState<ScanConfig>({
    targets: '',
    scanType: 'quick',
    ports: '1-1000',
    excludeHosts: '',
    useNmap: true,
    useMasscan: false,
    extra: '',
    rate: 1000,
    detectOS: false,
    detectVersions: true,
    skipPing: false,
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const validateForm = (): boolean => {
    const newErrors: string[] = [];

    if (!config.targets.trim()) {
      newErrors.push('Target is required');
    }

    if (!config.useNmap && !config.useMasscan) {
      newErrors.push('Select at least one scanning tool');
    }

    if (config.rate !== undefined && (config.rate < 100 || config.rate > 100000)) {
      newErrors.push('Masscan rate must be between 100-100000');
    }

    setErrors(newErrors);
    return newErrors.length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    console.log('ScanForm handleSubmit called');
    e.preventDefault();

    console.log('Form config:', config);
    const isValid = validateForm();
    console.log('Form validation result:', isValid);
    console.log('Validation errors:', errors);

    if (isValid) {
      console.log('Calling onStartScan with config:', config);
      onStartScan(config);
    } else {
      console.log('Form validation failed, not calling onStartScan');
    }
  };

  const presetConfigs = {
    quick: { ports: '1-1000', detectVersions: true, detectOS: false },
    comprehensive: { ports: '1-65535', detectVersions: true, detectOS: true },
    stealth: { ports: '21,22,23,25,53,80,110,111,135,139,143,443,993,995', detectVersions: false, detectOS: false },
  };

  const handlePreset = (preset: keyof typeof presetConfigs) => {
    setConfig(prev => ({ ...prev, scanType: preset, ...presetConfigs[preset] }));
  };

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 p-6">
      <div className="flex items-center gap-2 mb-6">
        <Target className="w-5 h-5 text-blue-400" />
        <h2 className="text-xl font-semibold text-white">Network Scanner</h2>
      </div>

      {errors.length > 0 && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded">
          {errors.map((error, i) => (
            <div key={i} className="flex items-center gap-2 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4" />
              {error}
            </div>
          ))}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target Input */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Target(s) *
          </label>
          <textarea
            value={config.targets}
            onChange={(e) => setConfig(prev => ({ ...prev, targets: e.target.value }))}
            placeholder="192.168.1.0/24&#10;10.0.0.1-10.0.0.100&#10;example.com&#10;192.168.1.1"
            className="w-full h-20 px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 resize-none"
            disabled={isScanning}
          />
          <p className="mt-1 text-xs text-gray-400">
            IP addresses, CIDR ranges, hostnames (one per line)
          </p>
        </div>

        {/* Scan Type Presets */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Scan Type
          </label>
          <div className="grid grid-cols-3 gap-2">
            {Object.keys(presetConfigs).map((preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => handlePreset(preset as keyof typeof presetConfigs)}
                className={`p-3 rounded border transition-colors ${config.scanType === preset
                  ? 'bg-blue-600 border-blue-500 text-white'
                  : 'bg-gray-800 border-gray-600 text-gray-300 hover:bg-gray-700'
                  }`}
                disabled={isScanning}
              >
                <div className="flex items-center justify-center mb-1">
                  {preset === 'quick' && <Zap className="w-4 h-4" />}
                  {preset === 'comprehensive' && <Network className="w-4 h-4" />}
                  {preset === 'stealth' && <Shield className="w-4 h-4" />}
                </div>
                <div className="text-sm font-medium capitalize">{preset}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Scanning Tools */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Scanning Tools
          </label>
          <div className="space-y-2">
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={config.useNmap}
                onChange={(e) => setConfig(prev => ({ ...prev, useNmap: e.target.checked }))}
                className="rounded bg-gray-700 border-gray-600 text-blue-600"
                disabled={isScanning}
              />
              <span className="ml-2 text-sm text-gray-300">
                Nmap (detailed scanning & service detection)
              </span>
            </label>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={config.useMasscan}
                onChange={(e) => setConfig(prev => ({ ...prev, useMasscan: e.target.checked }))}
                className="rounded bg-gray-700 border-gray-600 text-blue-600"
                disabled={isScanning}
              />
              <span className="ml-2 text-sm text-gray-300">
                Masscan (ultra-fast port discovery)
              </span>
            </label>
          </div>
        </div>

        {/* Advanced Options */}
        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors"
            disabled={isScanning}
          >
            <Settings className="w-4 h-4" />
            Advanced Options
          </button>

          {showAdvanced && (
            <div className="mt-4 space-y-4 pl-4 border-l-2 border-gray-700">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Port Range
                  </label>
                  <input
                    type="text"
                    value={config.ports}
                    onChange={(e) => setConfig(prev => ({ ...prev, ports: e.target.value }))}
                    placeholder="80,443,1-1000"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Exclude Hosts
                  </label>
                  <input
                    type="text"
                    value={config.excludeHosts}
                    onChange={(e) => setConfig(prev => ({ ...prev, excludeHosts: e.target.value }))}
                    placeholder="192.168.1.1,192.168.1.254"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
              </div>

              {config.useMasscan && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Masscan Rate (packets/sec)
                  </label>
                  <input
                    type="number"
                    value={config.rate}
                    onChange={(e) => setConfig(prev => ({ ...prev, rate: parseInt(e.target.value) }))}
                    min="100"
                    max="100000"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
              )}

              {config.useNmap && (
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">
                    Additional Nmap Options
                  </label>
                  <input
                    type="text"
                    value={config.extra}
                    onChange={(e) => setConfig(prev => ({ ...prev, extra: e.target.value }))}
                    placeholder="-T4 --script vuln"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
              )}

              <div className="space-y-2">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={config.detectOS}
                    onChange={(e) => setConfig(prev => ({ ...prev, detectOS: e.target.checked }))}
                    className="rounded bg-gray-700 border-gray-600 text-blue-600"
                    disabled={isScanning}
                  />
                  <span className="ml-2 text-sm text-gray-300">OS Detection</span>
                </label>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={config.detectVersions}
                    onChange={(e) => setConfig(prev => ({ ...prev, detectVersions: e.target.checked }))}
                    className="rounded bg-gray-700 border-gray-600 text-blue-600"
                    disabled={isScanning}
                  />
                  <span className="ml-2 text-sm text-gray-300">Version Detection</span>
                </label>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={config.skipPing}
                    onChange={(e) => setConfig(prev => ({ ...prev, skipPing: e.target.checked }))}
                    className="rounded bg-gray-700 border-gray-600 text-blue-600"
                    disabled={isScanning}
                  />
                  <span className="ml-2 text-sm text-gray-300">Skip Host Discovery (-Pn)</span>
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Submit/Cancel Buttons */}
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={isScanning || !config.targets.trim()}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-medium rounded transition-colors"
          >
            {isScanning ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Start Scan
              </>
            )}
          </button>
          
          {isScanning && onCancelScan && (
            <button
              type="button"
              onClick={onCancelScan}
              className="bg-red-600 hover:bg-red-700 text-white font-medium py-3 px-4 rounded transition-colors flex items-center justify-center gap-2"
            >
              <Square className="w-4 h-4" />
              Stop
            </button>
          )}
        </div>
      </form>
    </div>
  );
};

export default ScanForm;