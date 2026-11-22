export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory = 'SECRET' | 'SCA' | 'SAST';

export interface Finding {
  category: FindingCategory;
  path: string;
  class?: string;
  line?: number;
  endLine?: number;
  severity: Severity;
  description?: string;
  remediation?: string;
  // SCA specific
  group?: string;
  artifact?: string;
  version?: string;
  advisoryId?: string;
  fixedVersions?: string[];
  [key: string]: any;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface AuditResult {
  status: 'passed' | 'failed';
  exitCode: number;
  summary: AuditSummary;
  reportUrl?: string;
  findings: Finding[];
  jsonReport?: {
    findings: Finding[];
  };
  totalFindings: number;
}

export interface ScenarioTemplate {
  id: string;
  title: string;
  category: string;
  description: string;
  graph?: any;
}
