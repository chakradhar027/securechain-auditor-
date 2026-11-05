import React from 'react';
import { ShieldCheck, Activity, Cpu, Layers, FileCheck } from 'lucide-react';

interface Props {
  progressPercent: number;
  currentStep: string;
  isScanning: boolean;
}

export const ScanProgress: React.FC<Props> = ({ progressPercent, currentStep, isScanning }) => {
  if (!isScanning && progressPercent === 0) return null;

  const stages = [
    { name: 'Slither Static Analysis', icon: Layers, minPercent: 20 },
    { name: 'Mythril Symbolic Execution', icon: Cpu, minPercent: 40 },
    { name: 'Custom Detectors (CEI, Auth, Oracles)', icon: Activity, minPercent: 60 },
    { name: 'Foundry Dynamic Invariant Fuzzing', icon: ShieldCheck, minPercent: 80 },
    { name: 'Risk Scoring & ReportLab PDF Report', icon: FileCheck, minPercent: 95 },
  ];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl backdrop-blur-sm space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-cyan-400 animate-spin" />
          <h4 className="text-sm font-semibold text-slate-100">Multi-Engine Audit Pipeline</h4>
        </div>
        <span className="text-sm font-mono font-bold text-cyan-400">{progressPercent}%</span>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-slate-950 rounded-full h-2.5 overflow-hidden border border-slate-800">
        <div
          className="bg-gradient-to-r from-cyan-500 to-blue-600 h-2.5 rounded-full transition-all duration-300 shadow-lg shadow-cyan-500/50"
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      <p className="text-xs text-slate-400 italic">
        Current Activity: <span className="text-slate-200 font-medium">{currentStep}</span>
      </p>

      {/* Step Badges */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2 pt-2">
        {stages.map((stage, idx) => {
          const isDone = progressPercent >= stage.minPercent;
          const isCurrent = progressPercent < stage.minPercent && (idx === 0 || progressPercent >= stages[idx - 1].minPercent);
          const Icon = stage.icon;

          return (
            <div
              key={idx}
              className={`p-2.5 rounded-lg border text-xs flex items-center space-x-2 transition-all ${
                isDone
                  ? 'bg-cyan-950/40 border-cyan-800/60 text-cyan-300'
                  : isCurrent
                  ? 'bg-slate-800/80 border-cyan-500/80 text-white animate-pulse'
                  : 'bg-slate-950/40 border-slate-800 text-slate-500'
              }`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span className="truncate">{stage.name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
