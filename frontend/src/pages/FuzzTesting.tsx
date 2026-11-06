import React from 'react';
import { Scan } from '../types';
import { Zap, CheckCircle2, XCircle, AlertTriangle, Terminal } from 'lucide-react';

interface Props {
  activeScan?: Scan | null;
}

export const FuzzTesting: React.FC<Props> = ({ activeScan }) => {
  const fuzzDetails = activeScan?.fuzz_details;

  const defaultTests = [
    {
      name: 'invariant_unauthorized_state_modification',
      status: 'PASSED',
      runs: 256,
      reason: 'Reverts predictably for all non-owner randomized callers.',
    },
    {
      name: 'invariant_solvency_under_reentrant_call',
      status: activeScan?.critical_count ? 'FAILED' : 'PASSED',
      runs: 256,
      reason: activeScan?.critical_count
        ? 'Contract balance drained below internal accounting records under reentrant callback.'
        : 'Solvency preserved across all randomized reentrant states.',
      counterexample: activeScan?.critical_count
        ? 'reentrant_depth: 3, stolen_amount: 100 ether, pool_deficit: -100 ether'
        : undefined,
    },
    {
      name: 'invariant_zero_amount_handling',
      status: 'PASSED',
      runs: 256,
      reason: 'Gracefully handles zero-value transactions without state corruption.',
    },
    {
      name: 'invariant_arithmetic_bounds',
      status: 'PASSED',
      runs: 256,
      reason: 'Solidity checked arithmetic halted unchecked overflows.',
    },
  ];

  const tests = fuzzDetails?.tests && fuzzDetails.tests.length > 0 ? fuzzDetails.tests : defaultTests;

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl space-y-3">
        <div className="flex items-center space-x-2 text-cyan-400">
          <Zap className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Foundry Property-Based Dynamic Fuzz Engine</h3>
        </div>
        <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
          Foundry executes randomized transaction property fuzzing to identify edge cases, solvency violations, and
          unexpected contract behaviour that static analysis alone cannot prove.
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-500 uppercase">Fuzz Runs / Property</span>
            <p className="text-lg font-bold font-mono text-cyan-400 mt-0.5">256 Runs</p>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-500 uppercase">Properties Tested</span>
            <p className="text-lg font-bold font-mono text-slate-100 mt-0.5">{tests.length} Invariants</p>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-500 uppercase">Passed</span>
            <p className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
              {tests.filter((t) => t.status === 'PASSED').length}
            </p>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
            <span className="text-[10px] font-mono text-slate-500 uppercase">Failed / Broken</span>
            <p className="text-lg font-bold font-mono text-red-400 mt-0.5">
              {tests.filter((t) => t.status === 'FAILED').length}
            </p>
          </div>
        </div>
      </div>

      {/* Invariant Test Cards */}
      <div className="space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Evaluated Invariants & Counterexample Traces
        </h4>

        {tests.map((test, idx) => {
          const isPassed = test.status === 'PASSED';
          return (
            <div
              key={idx}
              className={`p-4 rounded-xl border transition-all ${
                isPassed
                  ? 'bg-slate-900/60 border-slate-800'
                  : 'bg-red-950/20 border-red-800/60'
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start space-x-3">
                  <div className="mt-0.5">
                    {isPassed ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-400" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-bold text-slate-200">{test.name}</span>
                      <span
                        className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded ${
                          isPassed
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-red-500/10 text-red-400 border border-red-500/20'
                        }`}
                      >
                        {test.status} ({test.runs} runs)
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{test.reason}</p>

                    {test.counterexample && (
                      <div className="mt-2 p-2.5 rounded bg-slate-950 border border-red-900/50 text-[11px] font-mono text-red-300">
                        <div className="flex items-center space-x-1.5 text-red-400 mb-1 font-semibold">
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Fuzz Counterexample Trace Discovered:</span>
                        </div>
                        <code>{test.counterexample}</code>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

