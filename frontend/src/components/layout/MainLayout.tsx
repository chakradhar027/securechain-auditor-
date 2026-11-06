import React from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

interface Props {
  currentTab: string;
  onNavigate: (tab: string) => void;
  children: React.ReactNode;
}

export const MainLayout: React.FC<Props> = ({ currentTab, onNavigate, children }) => {
  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100 font-sans">
      <Sidebar currentTab={currentTab} onNavigate={onNavigate} />
      <div className="flex-1 flex flex-col min-w-0">
        <Header currentTab={currentTab} />
        <main className="flex-1 p-8 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
};

