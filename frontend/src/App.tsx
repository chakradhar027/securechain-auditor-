import React, { useState } from 'react';
import { MainLayout } from './components/layout/MainLayout';
import { Dashboard } from './pages/Dashboard';
import { Scanner } from './pages/Scanner';
import { Findings } from './pages/Findings';
import { ScanHistory } from './pages/ScanHistory';
import { FuzzTesting } from './pages/FuzzTesting';
import { Reports } from './pages/Reports';
import { Scan } from './types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [activeScan, setActiveScan] = useState<Scan | null>(null);

  const handleScanSelected = (scan: Scan) => {
    setActiveScan(scan);
  };

  return (
    <MainLayout currentTab={currentTab} onNavigate={setCurrentTab}>
      {currentTab === 'dashboard' && (
        <Dashboard
          onNavigate={setCurrentTab}
          onSelectScan={(scan) => {
            handleScanSelected(scan);
            setCurrentTab('scanner');
          }}
        />
      )}
      {currentTab === 'scanner' && (
        <Scanner
          activeScan={activeScan}
          onScanCompleted={(scan) => {
            setActiveScan(scan);
          }}
        />
      )}
      {currentTab === 'findings' && <Findings />}
      {currentTab === 'history' && (
        <ScanHistory
          onSelectScan={(scan) => {
            handleScanSelected(scan);
            setCurrentTab('scanner');
          }}
        />
      )}
      {currentTab === 'fuzzing' && <FuzzTesting activeScan={activeScan} />}
      {currentTab === 'reports' && <Reports />}
    </MainLayout>
  );
};

export default App;
