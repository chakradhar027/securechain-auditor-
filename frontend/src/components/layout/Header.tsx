import React from 'react';
import { ShieldCheck, Terminal, Bell } from 'lucide-react';

interface Props {
  currentTab: string;
}

export const Header: React.FC<Props> = ({ currentTab }) => {
  const tabTitles: Record<string, { title: string; subtitle: string }> = {
    dashboard: {
      title: 'Security Overview Dashboard',
      subtitle: 'Real-time telemetry, vulnerability densities, and audit statistics',
    },
    scanner: {
      title: 'Multi-Engine Smart Contract Scanner',
      subtitle: 'Upload Solidity code and execute Slither, Mythril, Foundry & Custom detection',
    },
    findings: {
      title: 'Vulnerability Findings Catalog',
      subtitle: 'Consolidated security vulnerabilities, evidence snippets, and remediations',
    },
    history: {
      title: 'Audit History & Comparisons',
      subtitle: 'Track previous security scans and review contract risk score evolution',
    },
    fuzzing: {
      title: 'Automated Foundry Dynamic Fuzz Testing',
      subtitle: 'Property-based state invariant fuzz runs and counterexample generation',
    },
    reports: {
      title: 'Security Audit Reports (PDF)',
      subtitle: 'Download formal audit certificates and ReportLab-generated documentation',
    },
  };

  const current = tabTitles[currentTab] || { title: 'SecureChain Auditor', subtitle: '' };

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/40 backdrop-blur-md px-8 flex items-center justify-between sticky top-0 z-20">
      <div>
        <h2 className="text-sm font-bold text-slate-100">{current.title}</h2>
        <p className="text-[11px] text-slate-400">{current.subtitle}</p>
      </div>

      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>API Connected</span>
        </div>
      </div>
    </header>
  );
};

