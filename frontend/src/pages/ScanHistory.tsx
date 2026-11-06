import React, { useEffect, useState } from 'react';
import { Scan } from '../types';
import { reportService } from '../services/reportService';
import { SeverityBadge } from '../components/findings/SeverityBadge';
import { Download, GitCompare, FileCode, CheckCircle, ArrowRight } from 'lucide-react';

interface Props {
  onSelectScan: (scan: Scan) => void;
}

export const ScanHistory: React.FC<Props> = ({ onSelectScan }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [compareA, setCompareA] = useState<number | null>(null);
  const [compareB, setCompareB] = useState<number | null>(null);
  const [diffResult, setDiffResult] = useState<any | null>(null);

  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    try {
      setLoading(true);
      const data = await reportService.getScanHistory();
      setScans(data);
    } catch (err) {
      console.error('Failed to load history', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCompare = async () => {
    if (!compareA || !compareB) return;
    try {
      const res = await reportService.compareScans(compareA, compareB);
      setDiffResult(res);
    } catch (err) {
      console.error('Failed to compare scans', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Version Comparison Card */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl space-y-4">
        <div className="flex items-center space-x-2 text-cyan-400">
          <GitCompare className="w-5 h-5" />
          <h3 className="text-sm font-semibold text-slate-100">Contract Version & Audit Diff</h3>
        </div>
        <p className="text-xs text-slate-400">
          Compare security improvements and risk delta across two audit iterations.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">Baseline Scan (Before)</label>
            <select
              value={compareA || ''}
              onChange={(e) => setCompareA(Number(e.target.value) || null)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">Select Audit A</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  SCA-{s.id.toString().padStart(6, '0')} - {s.contract_name || `Contract #${s.contract_id}`} ({s.risk_level})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-mono text-slate-400 mb-1">Patched Scan (After)</label>
            <select
              value={compareB || ''}
              onChange={(e) => setCompareB(Number(e.target.value) || null)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">Select Audit B</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  SCA-{s.id.toString().padStart(6, '0')} - {s.contract_name || `Contract #${s.contract_id}`} ({s.risk_level})
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-end">
            <button
              onClick={handleCompare}
              disabled={!compareA || !compareB || compareA === compareB}
              className="w-full px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-500 text-white rounded-lg text-xs font-semibold transition-colors"
            >
              Compute Audit Diff
            </button>
          </div>
        </div>

        {diffResult && (
          <div className="mt-4 p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-semibold">Audit Comparison Result</span>
              <span
                className={`font-mono font-bold px-2 py-0.5 rounded text-xs ${
                  diffResult.is_improved
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'bg-red-500/10 text-red-400 border border-red-500/20'
                }`}
              >
                {diffResult.is_improved ? 'Security Improved' : 'Risk Elevated'}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500">Scan A Risk</span>
                <p className="text-sm font-bold text-slate-200 mt-0.5">
                  {diffResult.scan_a.risk_score} ({diffResult.scan_a.risk_level})
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500">Scan B Risk</span>
                <p className="text-sm font-bold text-slate-200 mt-0.5">
                  {diffResult.scan_b.risk_score} ({diffResult.scan_b.risk_level})
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500">Risk Delta</span>
                <p
                  className={`text-sm font-bold mt-0.5 ${
                    diffResult.risk_delta < 0 ? 'text-emerald-400' : 'text-red-400'
                  }`}
                >
                  {diffResult.risk_delta > 0 ? `+${diffResult.risk_delta}` : diffResult.risk_delta} pts
                </p>
              </div>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                <span className="text-[10px] text-slate-500">Vuln Delta</span>
                <p
                  className={`text-sm font-bold mt-0.5 ${
                    diffResult.vuln_delta < 0 ? 'text-emerald-400' : 'text-red-400'
                  }`}
                >
                  {diffResult.vuln_delta > 0 ? `+${diffResult.vuln_delta}` : diffResult.vuln_delta} issues
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* History Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl">
        <h4 className="text-sm font-semibold text-slate-100 mb-4">Historical Audit Registry</h4>
        {loading ? (
          <div className="py-8 text-center text-slate-500 text-xs">Loading audit registry...</div>
        ) : scans.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs">No audit history found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-3">Audit ID</th>
                  <th className="py-2.5 px-3">Contract</th>
                  <th className="py-2.5 px-3">Risk Level</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Vulnerabilities</th>
                  <th className="py-2.5 px-3">Fuzz Invariants</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3 text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan)}
                    className="hover:bg-slate-850/60 transition-colors cursor-pointer"
                  >
                    <td className="py-3 px-3 font-mono text-cyan-400 font-medium">
                      SCA-{scan.id.toString().padStart(6, '0')}
                    </td>
                    <td className="py-3 px-3 font-semibold text-slate-200">
                      {scan.contract_name || `Contract #${scan.contract_id}`}
                    </td>
                    <td className="py-3 px-3">
                      <SeverityBadge severity={scan.risk_level} size="sm" />
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-slate-100">
                      {scan.risk_score.toFixed(1)}/100
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <span className="text-red-400">{scan.critical_count}C</span>{' '}
                      <span className="text-orange-400">{scan.high_count}H</span>{' '}
                      <span className="text-amber-400">{scan.medium_count}M</span>{' '}
                      <span className="text-blue-400">{scan.low_count}L</span>
                    </td>
                    <td className="py-3 px-3 font-mono text-emerald-400">
                      {scan.fuzz_passed}/{scan.fuzz_total} Passed
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {new Date(scan.started_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <a
                        href={reportService.getDownloadReportUrl(scan.id)}
                        download
                        className="p-1 hover:text-cyan-400 text-slate-400 inline-block"
                        title="Download PDF"
                      >
                        <Download className="w-4 h-4" />
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

