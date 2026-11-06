import React, { useEffect, useState } from 'react';
import { StatCard } from '../components/dashboard/StatCard';
import { VulnerabilityChart } from '../components/dashboard/VulnerabilityChart';
import { RecentScans } from '../components/dashboard/RecentScans';
import { ScanSummary, Scan } from '../types';
import { reportService } from '../services/reportService';
import { ShieldAlert, ShieldCheck, Bug, Activity, Plus } from 'lucide-react';

interface Props {
  onNavigate: (tab: string) => void;
  onSelectScan: (scan: Scan) => void;
}

export const Dashboard: React.FC<Props> = ({ onNavigate, onSelectScan }) => {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSummary();
  }, []);

  const loadSummary = async () => {
    try {
      setLoading(true);
      const data = await reportService.getDashboardSummary();
      setSummary(data);
    } catch (err) {
      console.error('Failed to load dashboard summary', err);
    } finally {
      setLoading(false);
    }
  };

  const criticalCount = summary?.recent_scans.reduce((acc, s) => acc + s.critical_count, 0) || 0;
  const highCount = summary?.recent_scans.reduce((acc, s) => acc + s.high_count, 0) || 0;
  const mediumCount = summary?.recent_scans.reduce((acc, s) => acc + s.medium_count, 0) || 0;
  const lowCount = summary?.recent_scans.reduce((acc, s) => acc + s.low_count, 0) || 0;
  const infoCount = summary?.recent_scans.reduce((acc, s) => acc + s.info_count, 0) || 0;

  return (
    <div className="space-y-6">
      {/* Action banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-cyan-950/40 border border-slate-800 shadow-xl gap-4">
        <div>
          <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-cyan-400 bg-cyan-950/80 px-2.5 py-1 rounded-full border border-cyan-800/60">
            Intelligent Multi-Engine Security
          </span>
          <h2 className="text-xl font-bold text-white mt-2">Smart Contract Security Posture</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Correlated static, symbolic, and dynamic fuzz vulnerability analysis for Solidity smart contracts.
          </p>
        </div>
        <button
          onClick={() => onNavigate('scanner')}
          className="flex items-center space-x-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-cyan-500/20 active:scale-95 transition-all"
        >
          <Plus className="w-4 h-4" />
          <span>New Contract Audit</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Audits"
          value={summary?.total_scans || 0}
          subtitle="Contracts analyzed"
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Critical Threats"
          value={summary?.critical_scans || 0}
          subtitle="High risk contracts"
          icon={ShieldAlert}
          color="red"
        />
        <StatCard
          title="Total Findings"
          value={summary?.total_vulnerabilities || 0}
          subtitle="Deduplicated issues"
          icon={Bug}
          color="amber"
        />
        <StatCard
          title="Avg Risk Score"
          value={`${summary?.average_risk_score.toFixed(1) || '0.0'}/100`}
          subtitle="Fleet exposure index"
          icon={ShieldCheck}
          color="emerald"
        />
      </div>

      {/* Severity Distribution Chart */}
      <VulnerabilityChart
        critical={criticalCount}
        high={highCount}
        medium={mediumCount}
        low={lowCount}
        info={infoCount}
      />

      {/* Recent Scans Table */}
      <RecentScans
        scans={summary?.recent_scans || []}
        onSelectScan={(s) => {
          onSelectScan(s);
          onNavigate('scanner');
        }}
      />
    </div>
  );
};

