import React from 'react';
import { LucideIcon } from 'lucide-react';

interface Props {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color?: 'cyan' | 'red' | 'amber' | 'emerald' | 'blue';
}

export const StatCard: React.FC<Props> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color = 'cyan',
}) => {
  const colorStyles = {
    cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
    amber: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    emerald: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-lg backdrop-blur-sm">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</p>
          <h3 className="text-2xl font-bold font-mono text-slate-100 mt-1">{value}</h3>
          {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-xl border ${colorStyles[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
