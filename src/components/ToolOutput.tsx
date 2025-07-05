// LEGION2 - A free and open-source penetration testing tool.
// Copyright (c) 2025 NubleX / Igor Dunaev

import React, { useState, useRef, useEffect } from 'react';
import { Terminal, Copy, Download, Filter, Search, ChevronDown, ChevronUp } from 'lucide-react';

interface ToolOutputProps {
  className?: string;
  outputs: ToolOutput[];
  isLive?: boolean;
}

interface ToolOutput {
  id: string;
  tool: string;
  command: string;
  timestamp: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  duration: number;
  isRunning?: boolean;
}

const ToolOutput: React.FC<ToolOutputProps> = ({ outputs, isLive = false }) => {
  const [selectedTool, setSelectedTool] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showErrors, setShowErrors] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const [expandedOutputs, setExpandedOutputs] = useState<Set<string>>(new Set());
  
  const bottomRef = useRef<HTMLDivElement>(null);

  const tools = ['all', ...Array.from(new Set(outputs.map(o => o.tool)))];
  
  const filteredOutputs = outputs.filter(output => {
    if (selectedTool !== 'all' && output.tool !== selectedTool) return false;
    if (!showErrors && output.stderr) return false;
    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return output.command.toLowerCase().includes(searchLower) ||
             output.stdout.toLowerCase().includes(searchLower) ||
             output.stderr.toLowerCase().includes(searchLower);
    }
    return true;
  });

  useEffect(() => {
    if (autoScroll && isLive && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [outputs, autoScroll, isLive]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const exportOutput = () => {
    const data = filteredOutputs.map(output => ({
      tool: output.tool,
      command: output.command,
      timestamp: output.timestamp,
      stdout: output.stdout,
      stderr: output.stderr,
      exitCode: output.exitCode,
      duration: output.duration
    }));
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'tool-output.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleExpanded = (id: string) => {
    const newExpanded = new Set(expandedOutputs);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedOutputs(newExpanded);
  };

  const getStatusColor = (exitCode: number, isRunning?: boolean) => {
    if (isRunning) return 'text-yellow-400';
    return exitCode === 0 ? 'text-green-400' : 'text-red-400';
  };

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-700">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-green-400" />
            Tool Output ({filteredOutputs.length})
          </h2>
          
          <div className="flex items-center gap-2">
            {isLive && (
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="rounded bg-gray-700 border-gray-600"
                />
                Auto-scroll
              </label>
            )}
            <button
              onClick={exportOutput}
              className="p-2 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
              title="Export Output"
            >
              <Download className="w-4 h-4 text-gray-300" />
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search commands or output..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <select
            value={selectedTool}
            onChange={(e) => setSelectedTool(e.target.value)}
            className="px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500"
          >
            {tools.map(tool => (
              <option key={tool} value={tool}>
                {tool === 'all' ? 'All Tools' : tool}
              </option>
            ))}
          </select>

          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={showErrors}
              onChange={(e) => setShowErrors(e.target.checked)}
              className="rounded bg-gray-700 border-gray-600"
            />
            Show Errors
          </label>
        </div>
      </div>

      {/* Output List */}
      <div className="max-h-96 overflow-y-auto">
        {filteredOutputs.length === 0 ? (
          <div className="p-8 text-center text-gray-400">
            <Terminal className="w-12 h-12 mx-auto mb-2 opacity-50" />
            <p>No tool output available.</p>
          </div>
        ) : (
          <div className="space-y-2 p-4">
            {filteredOutputs.map((output) => {
              const isExpanded = expandedOutputs.has(output.id);
              const hasStderr = output.stderr && output.stderr.trim().length > 0;
              
              return (
                <div key={output.id} className="bg-gray-800 rounded border border-gray-700">
                  {/* Command Header */}
                  <div 
                    className="p-3 cursor-pointer hover:bg-gray-750 transition-colors"
                    onClick={() => toggleExpanded(output.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-gray-400" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-gray-400" />
                          )}
                          <span className="text-xs px-2 py-1 bg-gray-700 rounded font-mono">
                            {output.tool}
                          </span>
                        </div>
                        
                        <div className="flex-1 min-w-0">
                          <div className="font-mono text-sm text-white truncate">
                            {output.command}
                          </div>
                          <div className="flex items-center gap-4 text-xs text-gray-400 mt-1">
                            <span>{new Date(output.timestamp).toLocaleTimeString()}</span>
                            <span className={getStatusColor(output.exitCode, output.isRunning)}>
                              {output.isRunning ? 'Running...' : `Exit ${output.exitCode}`}
                            </span>
                            {!output.isRunning && (
                              <span>Duration: {formatDuration(output.duration)}</span>
                            )}
                            {hasStderr && (
                              <span className="text-red-400">Has Errors</span>
                            )}
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          copyToClipboard(output.command);
                        }}
                        className="p-1 hover:bg-gray-600 rounded transition-colors"
                        title="Copy Command"
                      >
                        <Copy className="w-3 h-3 text-gray-400" />
                      </button>
                    </div>
                  </div>

                  {/* Output Content */}
                  {isExpanded && (
                    <div className="border-t border-gray-700">
                      {output.stdout && (
                        <div className="p-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs text-green-400 font-medium">STDOUT</span>
                            <button
                              onClick={() => copyToClipboard(output.stdout)}
                              className="p-1 hover:bg-gray-600 rounded transition-colors"
                              title="Copy Output"
                            >
                              <Copy className="w-3 h-3 text-gray-400" />
                            </button>
                          </div>
                          <pre className="bg-gray-900 p-3 rounded text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap">
                            {output.stdout}
                          </pre>
                        </div>
                      )}

                      {hasStderr && (
                        <div className="p-3 border-t border-gray-700">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs text-red-400 font-medium">STDERR</span>
                            <button
                              onClick={() => copyToClipboard(output.stderr)}
                              className="p-1 hover:bg-gray-600 rounded transition-colors"
                              title="Copy Error"
                            >
                              <Copy className="w-3 h-3 text-gray-400" />
                            </button>
                          </div>
                          <pre className="bg-red-900/20 p-3 rounded text-xs text-red-300 overflow-x-auto whitespace-pre-wrap">
                            {output.stderr}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};

export default ToolOutput;