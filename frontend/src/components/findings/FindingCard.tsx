import React, { useState } from 'react';
import { Finding } from '../../types';
import { SeverityBadge } from './SeverityBadge';
import { CodeEvidence } from './CodeEvidence';
import { ChevronDown, ChevronUp, ShieldAlert, Cpu, CheckCircle2 } from 'lucide-react';

interface Props {
  finding: Finding;
  defaultExpanded?: boolean;
}

export const FindingCard: React.FC<Props> = ({ finding, defaultExpanded = false }) => {
  const [expanded, setExpanded] = useState(defaultExpanded);

  const categoryLabels: Record<string, string> = {
    REENTRANCY: 'Reentrancy Attack',
    ACCESS_CONTROL: 'Access Control & Auth',
    UNCHECKED_CALL: 'Unchecked External Call',
    ORACLE_MANIPULATION: 'Oracle & Price Manipulation',
    OTHER: 'Code Security & Hygiene',
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 hover:bg-slate-900/90 transition-all duration-200 overflow-hidden">
      <div
        onClick={() => setExpanded(!expanded)}
        className="p-4 cursor-pointer flex items-start justify-between gap-4 select-none"
      >
        <div className="flex items-start space-x-3 flex-1 min-w-0">
          <div className="mt-0.5 p-2 rounded-lg bg-slate-800/80 border border-slate-700/60 text-slate-300">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <SeverityBadge severity={finding.severity} size="sm" />
              <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                {categoryLabels[finding.category] || finding.category}
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/50 flex items-center gap-1">
                <Cpu className="w-3 h-3" />
                {finding.engine}
              </span>
              {finding.cwe_id && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/60 text-slate-400">
                  {finding.cwe_id}
                </span>
              )}
              {finding.swc_id && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/60 text-slate-400">
                  {finding.swc_id}
                </span>
              )}
            </div>
            <h4 className="text-sm font-semibold text-slate-100 truncate">{finding.title}</h4>
            <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
              {finding.description}
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-slate-400">
          <span className="text-xs font-mono font-medium text-slate-300 bg-slate-800 px-2 py-1 rounded">
            CVSS {finding.cvss_score.toFixed(1)}
          </span>
          <button className="p-1 hover:text-slate-200">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t border-slate-800/70 space-y-3 bg-slate-950/40">
          <div>
            <h5 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
              Vulnerability Explanation
            </h5>
            <p className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">
              {finding.description}
            </p>
          </div>

          <CodeEvidence
            snippet={finding.code_snippet}
            lineStart={finding.line_start}
            lineEnd={finding.line_end}
            filePath={finding.file_path}
          />

          <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/30 text-emerald-200 text-xs">
            <div className="flex items-center space-x-1.5 font-semibold text-emerald-400 mb-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Recommended Remediation</span>
            </div>
            <p className="whitespace-pre-wrap text-[11px] text-emerald-200/90 leading-relaxed font-sans">
              {finding.recommendation}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
