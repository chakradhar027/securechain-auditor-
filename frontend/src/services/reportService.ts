import { request } from './api';
import { Finding, Scan, ScanSummary } from '../types';

export const reportService = {
  async getScanHistory(): Promise<Scan[]> {
    return request<Scan[]>('/history/?limit=100');
  },

  async getDashboardSummary(): Promise<ScanSummary> {
    return request<ScanSummary>('/history/summary');
  },

  async getFindings(filters?: {
    scan_id?: number;
    severity?: string;
    category?: string;
  }): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (filters?.scan_id) params.append('scan_id', filters.scan_id.toString());
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.category) params.append('category', filters.category);
    return request<Finding[]>(`/findings/?${params.toString()}`);
  },

  getDownloadReportUrl(scanId: number): string {
    return `/api/v1/reports/download/${scanId}`;
  },

  async compareScans(scanA: number, scanB: number): Promise<any> {
    return request(`/history/compare?scan_id_a=${scanA}&scan_id_b=${scanB}`);
  },
};

