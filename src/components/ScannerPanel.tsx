import { useState, useEffect, useRef } from 'react';
import { Play, Square, Terminal, Trash2 } from 'lucide-react';
import { useLegionStore } from '../stores/legionStore';

const ScannerPanel = () => {
  const [targetIp, setTargetIp] = useState('192.168.1.0/24');
  const [scanType, setScanType] = useState('quick');
  const verboseOutputRef = useRef<HTMLDivElement>(null);
  
  const {
    currentScan,
    isScanning,
    verboseOutput,
    startScan,
    stopScan,
    clearVerboseOutput
  } = useLegionStore();

  // Auto-scroll verbose output
  useEffect(() => {
    if (verboseOutputRef.current) {
      verboseOutputRef.current.scrollTop = verboseOutputRef.current.scrollHeight;
    }
  }, [verboseOutput]);

  const handleStartScan = async () => {
    try {
      await startScan(targetIp, scanType);
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
    <div className="flex flex-col h-full space-y-6">
      {/* Scan Controls */}
      <div className="bg-gray-900 rounded-lg border border-gray-700 p-6">
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Terminal className="w-5 h-5 text-blue-400" />
          Network Scanner
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label htmlFor="target-ip" className="block text-sm font-medium text-gray-300 mb-2">
              Target IP/Network
            </label>
            <input
              id="target-ip"
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              disabled={isScanning}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:border-blue-500 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
              placeholder="192.168.1.0/24"
            />
          </div>
          
          <div>
            <label htmlFor="scan-type" className="block text-sm font-medium text-gray-300 mb-2">
              Scan Type
            </label>
            <select
              id="scan-type"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              disabled={isScanning}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:border-blue-500 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <option value="quick">Quick Scan (-T4 -F)</option>
              <option value="full">Full Scan (-p- -sV)</option>
              <option value="stealth">Stealth Scan (-sS)</option>
            </select>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          {!isScanning ? (
            <button
              onClick={handleStartScan}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium flex items-center gap-2 transition-colors"
            >
              <Play className="w-4 h-4" />
              Start Scan
            </button>
          ) : (
            <button
              onClick={handleStopScan}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium flex items-center gap-2 transition-colors"
            >
              <Square className="w-4 h-4" />
              Cancel Scan
            </button>
          )}
          
          {currentScan && (
            <div className="flex-1 flex items-center gap-3">
              <span className="text-sm text-gray-400">Progress:</span>
              <div className="flex-1 bg-gray-700 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-blue-500 h-full transition-all duration-300 ease-out"
                  style={{ width: `${currentScan.progress}%` }}
                />
              </div>
              <span className="text-sm text-gray-400 min-w-[50px] text-right">
                {currentScan.progress.toFixed(1)}%
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Verbose Output Window */}
      <div className="flex-1 bg-gray-900 rounded-lg border border-gray-700 flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <h3 className="font-semibold flex items-center gap-2">
            <Terminal className="w-4 h-4 text-gray-400" />
            Verbose Output
          </h3>
          <button
            onClick={clearVerboseOutput}
            className="px-3 py-1 text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 rounded flex items-center gap-1 transition-colors"
          >
            <Trash2 className="w-3 h-3" />
            Clear
          </button>
        </div>
        
        <div
          ref={verboseOutputRef}
          className="flex-1 p-4 overflow-y-auto font-mono text-sm bg-black"
          style={{ minHeight: '300px' }}
        >
          {verboseOutput.length === 0 ? (
            <div className="text-gray-500 italic">
              No output yet. Start a scan to see verbose output.
            </div>
          ) : (
            <div className="space-y-1">
              {verboseOutput.map((line, index) => (
                <div key={index} className="text-green-400 whitespace-pre-wrap break-all">
                  {line}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScannerPanel;