export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'SECURE';

export type VulnerabilityCategory =
  | 'REENTRANCY'
  | 'ACCESS_CONTROL'
  | 'UNCHECKED_CALL'
  | 'ORACLE_MANIPULATION'
  | 'OTHER';

export interface Contract {
  id: number;
  name: string;
  filename: string;
  file_path: string;
  source_code: string;
  byte_size: number;
  compiler_version: string;
  address?: string;
  network?: string;
  created_at: string;
}

export interface Finding {
  id: number;
  scan_id: number;
  title: string;
  category: VulnerabilityCategory;
  severity: SeverityLevel;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  engine: string;
  description: string;
  recommendation: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  cwe_id?: string;
  swc_id?: string;
  cvss_score: number;
}

export interface FuzzTestResult {
  name: string;
  status: 'PASSED' | 'FAILED';
  runs: number;
  reason?: string;
  counterexample?: string;
}

export interface FuzzDetails {
  total: number;
  passed: number;
  failed: number;
  runs_per_test?: number;
  tests: FuzzTestResult[];
}

export interface Scan {
  id: number;
  contract_id: number;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  engines_used: string[];
  risk_score: number;
  risk_level: SeverityLevel;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  fuzz_passed: number;
  fuzz_total: number;
  fuzz_details: FuzzDetails;
  report_path?: string;
  error_message?: string;
  started_at: string;
  completed_at?: string;
  findings?: Finding[];
}

export interface ScanSummary {
  total_scans: number;
  critical_scans: number;
  high_scans: number;
  total_vulnerabilities: number;
  average_risk_score: number;
  recent_scans: Scan[];
}

export interface EngineInfo {
  id: string;
  name: string;
  type: string;
  capabilities: string[];
  status: string;
}
