import React from 'react';
import {
  LayoutDashboard,
  ScanLine,
  ShieldAlert,
  History,
  Zap,
  FileText,
  Shield,
  Activity,
} from 'lucide-react';

interface Props {
  currentTab: string;
  onNavigate: (tab: string) => void;
}

export const Sidebar: React.FC<Props> = ({ currentTab, onNavigate }) => {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scanner', label: 'Security Scanner', icon: ScanLine },
    { id: 'findings', label: 'Findings Catalog', icon: ShieldAlert },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'fuzzing', label: 'Foundry Fuzz Testing', icon: Zap },
    { id: 'reports', label: 'Audit Reports (PDF)', icon: FileText },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col shrink-0 min-h-screen">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800 flex items-center space-x-3">
        <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl shadow-lg shadow-cyan-500/20 text-white">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <h1 className="font-bold text-sm tracking-wide text-white">SecureChain</h1>
          <p className="text-[10px] text-cyan-400 font-mono uppercase tracking-wider font-semibold">
            Security Auditor
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[10px] font-mono text-slate-500 uppercase tracking-wider">
          Security Platform
        </div>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Engine Status Footer */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/40 text-xs">
        <div className="flex items-center space-x-2 text-slate-300 font-semibold mb-2">
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-[11px]">Audit Engine Stack</span>
        </div>
        <div className="space-y-1 text-[11px] font-mono text-slate-400">
          <div className="flex justify-between">
            <span>Custom AST:</span>
            <span className="text-emerald-400">Active</span>
          </div>
          <div className="flex justify-between">
            <span>Slither Static:</span>
            <span className="text-emerald-400">Ready</span>
          </div>
          <div className="flex justify-between">
            <span>Mythril Symbolic:</span>
            <span className="text-emerald-400">Ready</span>
          </div>
          <div className="flex justify-between">
            <span>Foundry Fuzz:</span>
            <span className="text-emerald-400">Ready</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
