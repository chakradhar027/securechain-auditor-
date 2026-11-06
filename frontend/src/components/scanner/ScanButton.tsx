import React from 'react';
import { Play, Shield, Cpu, Activity, Zap } from 'lucide-react';

interface Props {
  selectedEngines: string[];
  onToggleEngine: (engineId: string) => void;
  onStartScan: () => void;
  isScanning: boolean;
  disabled: boolean;
}

export const ScanButton: React.FC<Props> = ({
  selectedEngines,
  onToggleEngine,
  onStartScan,
  isScanning,
  disabled,
}) => {
  const engineOptions = [
    { id: 'custom', name: 'Custom Detectors', icon: Shield, desc: 'Reentrancy, Access Control, Unchecked Calls, Oracle Manipulation' },
    { id: 'slither', name: 'Slither Static', icon: Activity, desc: 'AST & CFG static analysis' },
    { id: 'mythril', name: 'Mythril Symbolic', icon: Cpu, desc: 'EVM symbolic path constraint solving (Requires Docker)' },
    { id: 'foundry', name: 'Foundry Fuzzing', icon: Zap, desc: 'Automated 256-run dynamic invariant fuzz tests' },
  ];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl backdrop-blur-sm space-y-5">
      <div>
        <h4 className="text-sm font-semibold text-slate-100">Analysis Engine Orchestration</h4>
        <p className="text-xs text-slate-400 mt-0.5">
          Select security scanning engines to execute against the target contract.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {engineOptions.map((eng) => {
          const isSelected = selectedEngines.includes(eng.id);
          const Icon = eng.icon;
          return (
            <div
              key={eng.id}
              onClick={() => !isScanning && onToggleEngine(eng.id)}
              className={`p-3 rounded-xl border cursor-pointer select-none transition-all ${
                isSelected
                  ? 'bg-cyan-950/40 border-cyan-500/80 text-white shadow-lg shadow-cyan-950/40'
                  : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
              } ${isScanning ? 'opacity-60 cursor-not-allowed' : ''}`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center space-x-2">
                  <Icon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span className="text-xs font-semibold">{eng.name}</span>
                </div>
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => {}}
                  className="rounded border-slate-700 text-cyan-500 focus:ring-0 cursor-pointer pointer-events-none"
                />
              </div>
              <p className="text-[11px] text-slate-400 leading-tight">{eng.desc}</p>
            </div>
          );
        })}
      </div>

      <div className="pt-2 flex items-center justify-end">
        <button
          onClick={onStartScan}
          disabled={disabled || isScanning || selectedEngines.length === 0}
          className={`flex items-center space-x-2 px-6 py-3 rounded-xl font-semibold text-sm shadow-xl transition-all ${
            disabled || isScanning || selectedEngines.length === 0
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
              : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-cyan-500/25 active:scale-95'
          }`}
        >
          <Play className="w-4 h-4 fill-current" />
          <span>{isScanning ? 'Executing Security Audit...' : 'Execute Multi-Engine Security Scan'}</span>
        </button>
      </div>
    </div>
  );
};

