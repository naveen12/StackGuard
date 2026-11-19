export type Severity = 'critical' | 'high' | 'moderate' | 'low' | 'safe';

export type TargetCategory = 'container' | 'node-lockfile' | 'go-module' | 'python-wheel';

export type RemediationStatus = 'open' | 'patched' | 'revoked' | 'ignored';

export type ScreenId = 'overview' | 'intake' | 'advisories' | 'graph' | 'targets' | 'remediation';

export interface BlastRadiusPath {
  root: string;
  hops: string[];
  serviceName: string;
  exposure: 'internet-facing' | 'internal-mesh' | 'build-pipeline';
}

export interface RemediationDiff {
  filePath: string;
  command: string;
  removedLine: string;
  addedLine: string;
  notes: string;
}

export interface Vulnerability {
  id: string;
  cveId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  cvssScore: number;
  cvssVector: string;
  epssScore: number; // 0 to 100 percentage
  isKev: boolean; // CISA Known Exploited Vulnerability
  title: string;
  advisory: string;
  targetId: string;
  targetName: string;
  targetCategory: TargetCategory;
  branch: string;
  detectedAt: string;
  digest: string;
  status: RemediationStatus;
  impactedPath: string[];
  blastRadius: BlastRadiusPath[];
  remediation: RemediationDiff;
  exploitPayload: Record<string, unknown>;
}

export interface ScanTarget {
  id: string;
  name: string;
  reference: string;
  category: TargetCategory;
  branch: string;
  digest: string;
  lastScanned: string;
  packageCount: number;
  signed: boolean;
  provenance: string;
  layers?: number;
  status: 'active' | 'scanning' | 'revoked';
}

export interface TelemetryTrendPoint {
  date: string;
  critical: number;
  high: number;
  moderate: number;
  remediated: number;
}
