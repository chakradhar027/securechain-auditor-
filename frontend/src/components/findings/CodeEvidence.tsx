import React from 'react';
import { Terminal } from 'lucide-react';

interface Props {
  snippet?: string;
  lineStart?: number;
  lineEnd?: number;
  filePath?: string;
}

export const CodeEvidence: React.FC<Props> = ({ snippet, lineStart, lineEnd, filePath }) => {
  if (!snippet) return null;

  return (
    <div className="mt-3 rounded-lg overflow-hidden border border-slate-800 bg-slate-900/90 text-slate-300 font-mono text-xs">
      <div className="bg-slate-950 px-3 py-1.5 border-b border-slate-800 flex items-center justify-between text-slate-400">
        <div className="flex items-center space-x-2">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-[11px] truncate max-w-xs">{filePath || 'Contract.sol'}</span>
        </div>
        {lineStart && (
          <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded">
            Lines {lineStart} {lineEnd && lineEnd !== lineStart ? `- ${lineEnd}` : ''}
          </span>
        )}
      </div>
      <div className="p-3 overflow-x-auto leading-relaxed">
        <pre className="text-slate-200">
          {snippet.split('\n').map((line, idx) => {
            const isHighlight = line.startsWith('>>');
            return (
              <div
                key={idx}
                className={`${
                  isHighlight
                    ? 'bg-red-500/15 text-red-200 font-bold px-1.5 -mx-1.5 rounded'
                    : 'text-slate-300'
                }`}
              >
                {line}
              </div>
            );
          })}
        </pre>
      </div>
    </div>
  );
};
