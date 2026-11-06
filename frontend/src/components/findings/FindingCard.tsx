import React, { useState } from 'react';
import { Finding } from '../../types';
import { SeverityBadge } from './SeverityBadge';
import { CodeEvidence } from './CodeEvidence';
import {
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Activity,
  MapPin,
  FileCode
} from 'lucide-react';

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

  // Split description and exploitability impact assessment if present
  let technicalDesc = finding.description;
  let impactAssessment = '';

  if (finding.description.includes('[Exploitability Assessment]:')) {
    const parts = finding.description.split('[Exploitability Assessment]:');
    technicalDesc = parts[0].trim();
    impactAssessment = parts[1].trim();
  } else if (finding.description.includes('Exploitability Assessment:')) {
    const parts = finding.description.split('Exploitability Assessment:');
    technicalDesc = parts[0].trim();
    impactAssessment = parts[1].trim();
  }

  const confidenceColor = {
    HIGH: 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50',
    MEDIUM: 'bg-amber-950/60 text-amber-400 border-amber-800/50',
    LOW: 'bg-slate-800 text-slate-400 border-slate-700',
  }[finding.confidence || 'MEDIUM'];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 hover:bg-slate-900/90 transition-all duration-200 overflow-hidden shadow-sm">
      <div
        onClick={() => setExpanded(!expanded)}
        className="p-4 cursor-pointer flex items-start justify-between gap-4 select-none"
      >
        <div className="flex items-start space-x-3 flex-1 min-w-0">
          <div className="mt-0.5 p-2 rounded-lg bg-slate-800/80 border border-slate-700/60 text-slate-300">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex-1 min-w-0">
            {/* Metadata Badges Bar */}
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              {/* 1. Severity */}
              <SeverityBadge severity={finding.severity} size="sm" />

              {/* 2. Vulnerability Category */}
              <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {categoryLabels[finding.category] || finding.category}
              </span>

              {/* 3. Confidence */}
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border flex items-center gap-1 ${confidenceColor}`}>
                <Activity className="w-2.5 h-2.5" />
                Confidence: {finding.confidence || 'MEDIUM'}
              </span>

              {/* 4. Detection Engine */}
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/50 flex items-center gap-1">
                <Cpu className="w-3 h-3" />
                {finding.engine}
              </span>

              {/* 5. Source Code Line Location */}
              {finding.line_start ? (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/50 flex items-center gap-1">
                  <MapPin className="w-2.5 h-2.5 text-indigo-400" />
                  Line {finding.line_start}
                  {finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : ''}
                </span>
              ) : null}

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
              {technicalDesc}
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
        <div className="px-4 pb-4 pt-2 border-t border-slate-800/70 space-y-3 bg-slate-950/40">
          {/* Detailed Technical Explanation */}
          <div>
            <h5 className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-slate-400" />
              Technical Vulnerability Details
            </h5>
            <p className="text-xs text-slate-300 whitespace-pre-wrap leading-relaxed font-sans bg-slate-900/40 p-3 rounded-lg border border-slate-800/50">
              {technicalDesc}
            </p>
          </div>

          {/* 7. Explanation of Impact / Exploitability */}
          {impactAssessment && (
            <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/30 text-amber-200 text-xs">
              <div className="flex items-center space-x-1.5 font-semibold text-amber-400 mb-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Explanation of Impact & Exploitability</span>
              </div>
              <p className="whitespace-pre-wrap text-[11px] text-amber-200/90 leading-relaxed font-sans">
                {impactAssessment}
              </p>
            </div>
          )}

          {/* 6. Code Evidence */}
          <CodeEvidence
            snippet={finding.code_snippet}
            lineStart={finding.line_start}
            lineEnd={finding.line_end}
            filePath={finding.file_path}
          />

          {/* 8. Recommended Remediation */}
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
