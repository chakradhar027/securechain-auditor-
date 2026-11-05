import React, { useState } from 'react';
import { Contract, Scan } from '../types';
import { ContractUpload } from '../components/scanner/ContractUpload';
import { ScanProgress } from '../components/scanner/ScanProgress';
import { ScanButton } from '../components/scanner/ScanButton';
import { FindingCard } from '../components/findings/FindingCard';
import { SeverityBadge } from '../components/findings/SeverityBadge';
import { scannerService } from '../../src/services/scannerService';
import { reportService } from '../services/reportService';
import { Download, RefreshCw, ShieldAlert, Zap, FileText } from 'lucide-react';

interface Props {
  activeScan?: Scan | null;
  onScanCompleted: (scan: Scan) => void;
}

export const Scanner: React.FC<Props> = ({ activeScan, onScanCompleted }) => {
  const [selectedContract, setSelectedContract] = useState<Contract | null>(null);
  const [selectedEngines, setSelectedEngines] = useState<string[]>([
    'custom',
    'slither',
    'mythril',
    'foundry',
  ]);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [scanResult, setScanResult] = useState<Scan | null>(activeScan || null);
  const [error, setError] = useState<string | null>(null);

  const toggleEngine = (id: string) => {
    setSelectedEngines((prev) =>
      prev.includes(id) ? prev.filter((e) => e !== id) : [...prev, id]
    );
  };

  const handleStartScan = async () => {
    if (!selectedContract) return;

    setIsScanning(true);
    setProgress(10);
    setCurrentStep('Dispatching multi-engine scan jobs...');
    setError(null);

    try {
      const scan = await scannerService.startScan(selectedContract.id, selectedEngines);
      setProgress(100);
      setCurrentStep('Audit complete');
      setScanResult(scan);
      onScanCompleted(scan);
    } catch (err: any) {
      setError(err.message || 'Scanning process failed');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Contract Upload / Code Paste */}
      <ContractUpload
        onContractReady={(contract) => {
          setSelectedContract(contract);
          setScanResult(null);
        }}
        selectedContract={selectedContract}
      />

      {/* Engine Selection & Trigger */}
      <ScanButton
        selectedEngines={selectedEngines}
        onToggleEngine={toggleEngine}
        onStartScan={handleStartScan}
        isScanning={isScanning}
        disabled={!selectedContract}
      />

      {/* Live Scan Progress */}
      <ScanProgress
        progressPercent={progress}
        currentStep={currentStep}
        isScanning={isScanning}
      />

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-200 text-xs">
          <strong>Scan Error:</strong> {error}
        </div>
      )}

      {/* Scan Results Presentation */}
      {scanResult && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-4">
            <div>
              <div className="flex items-center space-x-2">
                <SeverityBadge severity={scanResult.risk_level} size="lg" />
                <span className="text-xs font-mono text-slate-400">
                  Audit ID: SCA-{scanResult.id.toString().padStart(6, '0')}
                </span>
              </div>
              <h3 className="text-lg font-bold text-slate-100 mt-2">
                Security Audit Findings ({scanResult.total_vulnerabilities} Identified)
              </h3>
            </div>

            <div className="flex items-center space-x-3">
              <a
                href={reportService.getDownloadReportUrl(scanResult.id)}
                download
                className="flex items-center space-x-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-lg text-xs font-semibold border border-slate-700 shadow-md transition-colors"
              >
                <Download className="w-4 h-4 text-cyan-400" />
                <span>Download PDF Audit Report</span>
              </a>
            </div>
          </div>

          {/* Quick Metrics Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400">Risk Score</span>
              <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
                {scanResult.risk_score.toFixed(1)}/100
              </div>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400">Critical / High</span>
              <div className="text-2xl font-bold font-mono text-red-400 mt-1">
                {scanResult.critical_count + scanResult.high_count}
              </div>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400">Medium / Low</span>
              <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
                {scanResult.medium_count + scanResult.low_count}
              </div>
            </div>
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
              <span className="text-[10px] font-mono uppercase text-slate-400">Foundry Invariants</span>
              <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                {scanResult.fuzz_passed}/{scanResult.fuzz_total} Passed
              </div>
            </div>
          </div>

          {/* Findings List */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Consolidated Vulnerability Catalog
            </h4>

            {scanResult.findings && scanResult.findings.length > 0 ? (
              scanResult.findings.map((f) => (
                <FindingCard key={f.id} finding={f} defaultExpanded={f.severity === 'CRITICAL'} />
              ))
            ) : (
              <div className="p-8 text-center text-slate-500 text-xs bg-slate-950/30 rounded-xl border border-slate-800">
                No security vulnerabilities discovered in the audited smart contract.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
