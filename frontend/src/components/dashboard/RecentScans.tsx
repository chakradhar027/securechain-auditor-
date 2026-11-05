import React from 'react';
import { Scan } from '../../types';
import { SeverityBadge } from '../findings/SeverityBadge';
import { FileCode, Download, ChevronRight } from 'lucide-react';
import { reportService } from '../../services/reportService';

interface Props {
  scans: Scan[];
  onSelectScan: (scan: Scan) => void;
}

export const RecentScans: React.FC<Props> = ({ scans, onSelectScan }) => {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl backdrop-blur-sm space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-sm font-semibold text-slate-100">Recent Security Scans</h4>
          <p className="text-xs text-slate-400 mt-0.5">Historical smart contract vulnerability audits</p>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="py-8 text-center text-slate-500 text-xs">
          No audits performed yet. Go to Scanner to analyze your first smart contract.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-3">Audit ID</th>
                <th className="py-2.5 px-3">Contract</th>
                <th className="py-2.5 px-3">Risk Level</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Issues</th>
                <th className="py-2.5 px-3">Date</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
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
                    <div className="flex items-center space-x-1.5">
                      <FileCode className="w-3.5 h-3.5 text-slate-400" />
                      <span>Contract #{scan.contract_id}</span>
                    </div>
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
                    <span className="text-amber-400">{scan.medium_count}M</span>
                  </td>
                  <td className="py-3 px-3 text-slate-400">
                    {new Date(scan.started_at).toLocaleDateString()}
                  </td>
                  <td className="py-3 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end space-x-2">
                      <a
                        href={reportService.getDownloadReportUrl(scan.id)}
                        download
                        className="p-1 hover:text-cyan-400 text-slate-400"
                        title="Download PDF Audit Report"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </a>
                      <button
                        onClick={() => onSelectScan(scan)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center text-xs"
                      >
                        <span>View</span>
                        <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
