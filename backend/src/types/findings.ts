export type FindingCategory = 'SECRET' | 'SAST' | 'SCA';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface BaseFinding {
  category: FindingCategory;
  path: string;
  severity?: Severity;
  description?: string;
  remediation?: string;
}

export interface SecretFinding extends BaseFinding {
  category: 'SECRET';
  class: 'password' | 'api-key' | 'configuration-token' | 'secret-fallback' | 'recoverable-token' | string;
  line: number;
  endLine?: number;
}

export interface SastFinding extends BaseFinding {
  category: 'SAST';
  class: 'sql-injection' | 'tls-verification' | 'credentialed-cors' | 'route-authorization' | 'object-authorization' | string;
  line: number;
  endLine?: number;
}

export interface ScaFinding extends BaseFinding {
  category: 'SCA';
  group: string;
  artifact: string;
  version: string;
  advisoryId: string;
}

export type Finding = SecretFinding | SastFinding | ScaFinding;

export interface SubmissionReport {
  findings: Finding[];
}

export interface ControlItem {
  id: string;
  category: FindingCategory;
  path: string;
  line?: number;
  endLine?: number;
  group?: string;
  artifact?: string;
  version?: string;
  reason: string;
}
