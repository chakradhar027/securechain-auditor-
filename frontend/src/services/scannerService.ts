import { request } from './api';
import { Contract, Scan, EngineInfo } from '../types';

export const scannerService = {
  async uploadFile(file: File): Promise<Contract> {
    const formData = new FormData();
    formData.append('file', file);
    return request<Contract>('/upload/file', {
      method: 'POST',
      body: formData,
    });
  },

  async uploadCode(name: string, source_code: string): Promise<Contract> {
    const formData = new FormData();
    formData.append('name', name);
    formData.append('source_code', source_code);
    return request<Contract>('/upload/code', {
      method: 'POST',
      body: formData,
    });
  },

  async fetchOnChainContract(address: string, network: string = 'ethereum'): Promise<Contract> {
    return request<Contract>('/contracts/on-chain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, network }),
    });
  },

  async getContracts(): Promise<Contract[]> {
    return request<Contract[]>('/contracts/');
  },

  async getContract(id: number): Promise<Contract> {
    return request<Contract>(`/contracts/${id}`);
  },

  async startScan(contractId: number, engines: string[]): Promise<Scan> {
    return request<Scan>('/scanner/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contract_id: contractId, engines }),
    });
  },

  async getScanStatus(scanId: number): Promise<{
    scan_id: number;
    status: string;
    progress_percent: number;
    current_step: string;
    message?: string;
  }> {
    return request(`/scanner/status/${scanId}`);
  },

  async getAvailableEngines(): Promise<EngineInfo[]> {
    return request<EngineInfo[]>('/scanner/engines');
  },
};

