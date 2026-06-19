// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import { AlertCircle, Play, Settings, Square } from 'lucide-react';
import React, { useState } from 'react';
import { ScanConfig } from '../types/scanning';
import useAppStore from '../stores/appStore';

interface ScanFormProps {
  onStartScan: (config: ScanConfig) => Promise<void>;
  isScanning: boolean;
  className?: string;
}

type ScanMethod = '-sS' | '-sT' | '-sU' | '-sn';
type Timing = '-T1' | '-T2' | '-T3' | '-T4' | '-T5';

interface FlagState {
  allPorts: boolean;       // -p-
  serviceVersion: boolean; // -sV
  osDetection: boolean;    // -O
  aggressive: boolean;     // -A
  skipPing: boolean;       // -Pn
  fragPackets: boolean;    // -f
}

const ScanForm: React.FC<ScanFormProps> = ({ onStartScan, isScanning }) => {
  const cancelScan = useAppStore(state => state.cancelScan);

  const [targets, setTargets] = useState('');
  const [ports, setPorts] = useState('');
  const [excludeHosts, setExcludeHosts] = useState('');
  const [iface, setIface] = useState('');
  const [extra, setExtra] = useState('');
  const [rate, setRate] = useState(100000);

  const [scanMethod, setScanMethod] = useState<ScanMethod>('-sT');
  const [timing, setTiming] = useState<Timing>('-T3');
  const [flags, setFlags] = useState<FlagState>({
    allPorts: false,
    serviceVersion: true,
    osDetection: true,
    aggressive: false,
    skipPing: false,
    fragPackets: false,
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const toggleFlag = (key: keyof FlagState) => {
    setFlags(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const buildExtraArgs = (): string => {
    const args: string[] = [];

    args.push(scanMethod);
    args.push(timing);

    if (flags.allPorts) args.push('-p-');
    if (flags.serviceVersion) args.push('-sV');
    if (flags.osDetection) args.push('-O');
    if (flags.aggressive) args.push('-A');
    if (flags.skipPing) args.push('-Pn');
    if (flags.fragPackets) args.push('-f');

    if (extra.trim()) args.push(extra.trim());

    return args.join(' ');
  };

  const validateForm = (): boolean => {
    const newErrors: string[] = [];
    if (!targets.trim()) newErrors.push('Target is required');
    if (rate < 100 || rate > 100000) newErrors.push('Masscan rate must be between 100–100000');
    setErrors(newErrors);
    return newErrors.length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    const config: ScanConfig = {
      targets,
      scanType: 'quick',
      ports,
      excludeHosts,
      useNmap: true,
      useMasscan: true,
      extra: buildExtraArgs(),
      rate,
      detectOS: flags.osDetection || flags.aggressive,
      detectVersions: flags.serviceVersion || flags.aggressive,
      skipPing: flags.skipPing,
      interface: iface,
    };
    onStartScan(config);
  };

  const scanMethods: { value: ScanMethod; label: string; hint: string }[] = [
    { value: '-sS', label: '-sS', hint: 'SYN Stealth' },
    { value: '-sT', label: '-sT', hint: 'TCP Connect' },
    { value: '-sU', label: '-sU', hint: 'UDP' },
    { value: '-sn', label: '-sn', hint: 'Ping Only' },
  ];

  const timingLevels: { value: Timing; label: string; hint: string }[] = [
    { value: '-T1', label: 'T1', hint: 'Sneaky' },
    { value: '-T2', label: 'T2', hint: 'Polite' },
    { value: '-T3', label: 'T3', hint: 'Normal' },
    { value: '-T4', label: 'T4', hint: 'Aggressive' },
    { value: '-T5', label: 'T5', hint: 'Insane' },
  ];

  const flagButtons: { key: keyof FlagState; label: string; hint: string }[] = [
    { key: 'allPorts', label: '-p-', hint: 'All 65535 ports' },
    { key: 'serviceVersion', label: '-sV', hint: 'Service versions' },
    { key: 'osDetection', label: '-O', hint: 'OS detection' },
    { key: 'aggressive', label: '-A', hint: 'Aggressive (OS+sV+scripts)' },
    { key: 'skipPing', label: '-Pn', hint: 'Skip host discovery' },
    { key: 'fragPackets', label: '-f', hint: 'Fragment packets' },
  ];

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700 p-6">

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

      <form onSubmit={handleSubmit} className="space-y-5">

        {/* Target Input */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Target(s) *</label>
          <textarea
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="192.168.1.0/24&#10;10.0.0.1-10.0.0.100&#10;example.com"
            className="w-full h-20 px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 resize-none"
            disabled={isScanning}
          />
        </div>

        {/* Scan Method */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Scan Method</label>
          <div className="flex gap-2">
            {scanMethods.map(({ value, label, hint }) => (
              <button
                key={value}
                type="button"
                title={hint}
                onClick={() => setScanMethod(value)}
                disabled={isScanning}
                className={`flex-1 py-2 rounded border text-sm font-mono transition-colors ${
                  scanMethod === value
                    ? 'bg-blue-600 border-blue-500 text-white'
                    : 'bg-gray-800 border-gray-600 text-gray-300 hover:bg-gray-700'
                }`}
              >
                <div>{label}</div>
                <div className="text-xs text-gray-400 font-sans">{hint}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Timing */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Timing</label>
          <div className="flex gap-2">
            {timingLevels.map(({ value, label, hint }) => (
              <button
                key={value}
                type="button"
                title={hint}
                onClick={() => setTiming(value)}
                disabled={isScanning}
                className={`flex-1 py-2 rounded border text-sm font-mono transition-colors ${
                  timing === value
                    ? 'bg-purple-600 border-purple-500 text-white'
                    : 'bg-gray-800 border-gray-600 text-gray-300 hover:bg-gray-700'
                }`}
              >
                <div>{label}</div>
                <div className="text-xs text-gray-400 font-sans">{hint}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Flag Toggles */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Flags</label>
          <div className="grid grid-cols-3 gap-2">
            {flagButtons.map(({ key, label, hint }) => (
              <button
                key={key}
                type="button"
                title={hint}
                onClick={() => toggleFlag(key)}
                disabled={isScanning}
                className={`py-2 px-3 rounded border text-sm font-mono transition-colors text-left ${
                  flags[key]
                    ? 'bg-green-700 border-green-500 text-white'
                    : 'bg-gray-800 border-gray-600 text-gray-400 hover:bg-gray-700'
                }`}
              >
                <span className="font-bold">{label}</span>
                <span className="block text-xs font-sans text-gray-400">{hint}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Command preview */}
        <div className="bg-gray-800 rounded p-2 font-mono text-xs text-green-400 break-all">
          nmap {buildExtraArgs()}{ports ? ` -p ${ports}` : ''} {targets || '<target>'}
        </div>

        {/* Advanced Options */}
        <div>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors text-sm"
            disabled={isScanning}
          >
            <Settings className="w-4 h-4" />
            {showAdvanced ? 'Hide' : 'Show'} Advanced Options
          </button>

          {showAdvanced && (
            <div className="mt-4 space-y-4 pl-4 border-l-2 border-gray-700">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Port Range</label>
                  <input
                    type="text"
                    value={ports}
                    onChange={(e) => setPorts(e.target.value)}
                    placeholder="80,443,1-1000"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Exclude Hosts</label>
                  <input
                    type="text"
                    value={excludeHosts}
                    onChange={(e) => setExcludeHosts(e.target.value)}
                    placeholder="192.168.1.1,192.168.1.254"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Interface</label>
                  <input
                    type="text"
                    value={iface}
                    onChange={(e) => setIface(e.target.value)}
                    placeholder="eth0"
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Masscan Rate</label>
                  <input
                    type="number"
                    value={rate}
                    onChange={(e) => setRate(Number(e.target.value))}
                    min={100}
                    max={100000}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                    disabled={isScanning}
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Extra Nmap Args</label>
                <input
                  type="text"
                  value={extra}
                  onChange={(e) => setExtra(e.target.value)}
                  placeholder="--script vuln --open"
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
                  disabled={isScanning}
                />
              </div>
            </div>
          )}
        </div>

        {/* Submit/Cancel */}
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={isScanning || !targets.trim()}
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

          {isScanning && (
            <button
              type="button"
              onClick={cancelScan}
              className="bg-red-600 hover:bg-red-700 text-white font-medium py-3 px-4 rounded transition-colors flex items-center justify-center gap-2"
            >
              <Square className="w-4 h-4" />
              Cancel
            </button>
          )}
        </div>

      </form>
    </div>
  );
};

export default ScanForm;
