import React, { useState } from 'react';
import { UploadCloud, Code, Globe, FileText, CheckCircle2 } from 'lucide-react';
import { Contract } from '../../types';
import { scannerService } from '../../services/scannerService';

interface Props {
  onContractReady: (contract: Contract) => void;
  selectedContract?: Contract | null;
}

export const ContractUpload: React.FC<Props> = ({ onContractReady, selectedContract }) => {
  const [tab, setTab] = useState<'upload' | 'paste' | 'onchain'>('upload');
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Paste mode state
  const [contractName, setContractName] = useState('SimpleBank');
  const [sourceCode, setSourceCode] = useState(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] = 0;
    }
}`);

  // On-chain mode state
  const [address, setAddress] = useState('');
  const [network, setNetwork] = useState('ethereum');

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setError(null);
    try {
      const contract = await scannerService.uploadFile(file);
      onContractReady(contract);
    } catch (err: any) {
      setError(err.message || 'File upload failed');
    } finally {
      setIsUploading(false);
    }
  };

  const handleCodeSubmit = async () => {
    if (!sourceCode.trim()) {
      setError('Solidity source code cannot be empty.');
      return;
    }
    setIsUploading(true);
    setError(null);
    try {
      const contract = await scannerService.uploadCode(contractName, sourceCode);
      onContractReady(contract);
    } catch (err: any) {
      setError(err.message || 'Failed to submit contract code');
    } finally {
      setIsUploading(false);
    }
  };

  const handleOnChainFetch = async () => {
    if (!address.trim()) {
      setError('Please provide a valid contract address.');
      return;
    }
    setIsUploading(true);
    setError(null);
    try {
      const contract = await scannerService.fetchOnChainContract(address, network);
      onContractReady(contract);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch verified on-chain contract');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-xl backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
        <div>
          <h3 className="text-base font-semibold text-slate-100">Smart Contract Submission</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Upload a local Solidity file, paste raw code, or fetch verified source from block explorers.
          </p>
        </div>

        {selectedContract && (
          <div className="flex items-center space-x-2 text-xs bg-cyan-950/50 text-cyan-400 border border-cyan-800/60 px-3 py-1.5 rounded-lg">
            <CheckCircle2 className="w-4 h-4" />
            <span className="font-semibold">{selectedContract.name}</span>
            <span className="text-slate-400">({selectedContract.filename})</span>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 mb-5 space-x-2">
        <button
          onClick={() => { setTab('upload'); setError(null); }}
          className={`flex items-center space-x-2 pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors ${
            tab === 'upload'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <UploadCloud className="w-3.5 h-3.5" />
          <span>Upload .sol File</span>
        </button>

        <button
          onClick={() => { setTab('paste'); setError(null); }}
          className={`flex items-center space-x-2 pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors ${
            tab === 'paste'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Code className="w-3.5 h-3.5" />
          <span>Direct Code Paste</span>
        </button>

        <button
          onClick={() => { setTab('onchain'); setError(null); }}
          className={`flex items-center space-x-2 pb-2.5 px-3 text-xs font-semibold border-b-2 transition-colors ${
            tab === 'onchain'
              ? 'border-cyan-500 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>On-Chain Contract Address</span>
        </button>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-950/40 border border-red-800/60 text-red-300 text-xs">
          {error}
        </div>
      )}

      {/* Tab 1: File Upload */}
      {tab === 'upload' && (
        <label className="flex flex-col items-center justify-center p-8 border-2 border-dashed border-slate-700/80 rounded-xl hover:border-cyan-500/80 hover:bg-slate-850/40 cursor-pointer transition-all">
          <input
            type="file"
            accept=".sol"
            onChange={handleFileUpload}
            disabled={isUploading}
            className="hidden"
          />
          <div className="p-3 bg-cyan-950/50 text-cyan-400 rounded-full border border-cyan-800/60 mb-3">
            <UploadCloud className="w-6 h-6 animate-pulse" />
          </div>
          <span className="text-sm font-semibold text-slate-200">
            {isUploading ? 'Validating and uploading contract...' : 'Click or drag Solidity (.sol) file here'}
          </span>
          <span className="text-xs text-slate-500 mt-1">Maximum file size: 5 MB</span>
        </label>
      )}

      {/* Tab 2: Code Paste */}
      {tab === 'paste' && (
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Contract Name</label>
            <input
              type="text"
              value={contractName}
              onChange={(e) => setContractName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              placeholder="e.g. EtherStore"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Solidity Code</label>
            <textarea
              rows={10}
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              className="w-full font-mono bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 leading-relaxed"
            />
          </div>
          <button
            onClick={handleCodeSubmit}
            disabled={isUploading}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold shadow-md transition-colors"
          >
            {isUploading ? 'Registering Code...' : 'Register Contract Code'}
          </button>
        </div>
      )}

      {/* Tab 3: On-Chain Fetch */}
      {tab === 'onchain' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Contract Address (0x...)
              </label>
              <input
                type="text"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                placeholder="0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Network</label>
              <select
                value={network}
                onChange={(e) => setNetwork(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ethereum">Ethereum Mainnet</option>
                <option value="sepolia">Sepolia Testnet</option>
                <option value="bsc">BNB Smart Chain</option>
                <option value="polygon">Polygon PoS</option>
                <option value="arbitrum">Arbitrum One</option>
                <option value="optimism">OP Mainnet</option>
              </select>
            </div>
          </div>
          <button
            onClick={handleOnChainFetch}
            disabled={isUploading}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold shadow-md transition-colors"
          >
            {isUploading ? 'Querying Blockchain Explorer...' : 'Fetch Verified Source Code'}
          </button>
        </div>
      )}
    </div>
  );
};
