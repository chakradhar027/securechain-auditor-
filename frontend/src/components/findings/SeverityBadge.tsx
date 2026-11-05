import React from 'react';
import { SeverityLevel } from '../../types';

interface Props {
  severity: SeverityLevel;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = 'md' }) => {
  const styles: Record<SeverityLevel, string> = {
    CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30 shadow-red-500/10',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30 shadow-orange-500/10',
    MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/30 shadow-amber-500/10',
    LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/30 shadow-blue-500/10',
    INFORMATIONAL: 'bg-slate-500/10 text-slate-400 border-slate-500/30 shadow-slate-500/10',
    SECURE: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-emerald-500/10',
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3.5 py-1.5 font-semibold',
  };

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded-full border shadow-sm ${
        styles[severity] || styles.MEDIUM
      } ${sizeClasses[size]}`}
    >
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current animate-pulse" />
      {severity}
    </span>
  );
};
