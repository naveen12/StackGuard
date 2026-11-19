import { useMemo, useState } from 'react';
import {
  ArrowRight,
  Container,
  FileCode2,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Unlock,
} from 'lucide-react';
import { ScanTarget, ScreenId, Severity, TelemetryTrendPoint, Vulnerability } from '../types/security';
import { CveCard } from './CveCard';

interface TelemetryOverviewProps {
  vulnerabilities: Vulnerability[];
  targets: ScanTarget[];
  trend: TelemetryTrendPoint[];
  selectedBranch: string;
  onSelectVuln: (vuln: Vulnerability) => void;
  onQuickPatch: (vulnId: string) => void;
  onFilterBySeverity: (sev: Severity) => void;
  onNavigate: (screen: ScreenId) => void;
}

export function TelemetryOverview({
  vulnerabilities,
  targets,
  trend,
  selectedBranch,
  onSelectVuln,
  onQuickPatch,
  onFilterBySeverity,
  onNavigate,
}: TelemetryOverviewProps) {
  const [hoveredIdx, setHoveredIdx] = useState<number>(trend.length - 1);

  const counts = useMemo(() => {
    const open = vulnerabilities.filter((v) => v.status === 'open');
    return {
      critical: open.filter((v) => v.severity === 'critical').length,
      high: open.filter((v) => v.severity === 'high').length,
      moderate: open.filter((v) => v.severity === 'moderate').length,
      low: open.filter((v) => v.severity === 'low').length,
      remediated: vulnerabilities.filter((v) => v.status === 'patched').length,
      kevCount: open.filter((v) => v.isKev).length,
    };
  }, [vulnerabilities]);

  const priorityVulns = useMemo(() => {
    const rank: Record<Severity, number> = {
      critical: 0,
      high: 1,
      moderate: 2,
      low: 3,
      safe: 4,
    };
    return [...vulnerabilities]
      .sort((a, b) => {
        const aSev = a.status === 'patched' ? 'safe' : a.severity;
        const bSev = b.status === 'patched' ? 'safe' : b.severity;
        if (rank[aSev] !== rank[bSev]) return rank[aSev] - rank[bSev];
        return b.cvssScore - a.cvssScore;
      })
      .slice(0, 6);
  }, [vulnerabilities]);

  const containerTargets = targets.filter((t) => t.category === 'container');
  const lockfileTargets = targets.filter((t) => t.category !== 'container');

  // SVG Chart Geometry
  const chartW = 540;
  const chartH = 160;
  const padX = 20;
  const padY = 18;
  const maxRem = Math.max(...trend.map((d) => d.remediated), 40);
  const maxOpen = Math.max(...trend.map((d) => d.critical + d.high + d.moderate), 25);

  const toX = (i: number) =>
    padX + (i / Math.max(trend.length - 1, 1)) * (chartW - padX * 2);
  const toYOpen = (val: number) =>
    chartH - padY - (val / maxOpen) * (chartH - padY * 2);
  const toYRem = (val: number) =>
    chartH - padY - (val / maxRem) * (chartH - padY * 2);

  const activeExposurePath = trend
    .map((pt, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toYOpen(pt.critical + pt.high)}`)
    .join(' ');
  const remediatedPath = trend
    .map((pt, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toYRem(pt.remediated)}`)
    .join(' ');
  const activePoint = trend[hoveredIdx] ?? trend[trend.length - 1];

  const severityTiles: {
    id: Severity;
    label: string;
    count: number;
    accent: string;
    border: string;
    sub: string;
  }[] = [
    {
      id: 'critical',
      label: 'CRITICAL',
      count: counts.critical,
      accent: 'text-[#F87171]',
      border: counts.critical > 0 ? 'border-[#EF4444]/40 glow-critical' : 'border-[#334155]/40',
      sub: `${counts.kevCount} CISA KEV active`,
    },
    {
      id: 'high',
      label: 'HIGH',
      count: counts.high,
      accent: 'text-[#FB923C]',
      border: 'border-[#F97316]/30',
      sub: 'Privilege & secret risk',
    },
    {
      id: 'moderate',
      label: 'MODERATE',
      count: counts.moderate,
      accent: 'text-[#FBBF24]',
      border: 'border-[#F59E0B]/25',
      sub: 'Conditional exploit',
    },
    {
      id: 'low',
      label: 'LOW',
      count: counts.low,
      accent: 'text-[#94A3B8]',
      border: 'border-[#64748B]/30',
      sub: 'Build-time / minor',
    },
    {
      id: 'safe',
      label: 'REMEDIATED',
      count: counts.remediated,
      accent: 'text-[#34D399]',
      border: 'border-[#10B981]/30',
      sub: 'Verified digest hashes',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Section 1: Threat Severity Telemetry Matrix */}
      <section aria-label="Severity telemetry breakdown" className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <div>
            <h1 className="font-display text-[24px] sm:text-[28px] font-semibold tracking-[-0.02em] text-[#DFE2EF]">
              Threat Telemetry Overview
            </h1>
            <p className="text-[14px] text-[#94A3B8] mt-0.5">
              Supply-chain posture for branch{' '}
              <span className="font-mono text-[#8ED5FF]">{selectedBranch}</span> across{' '}
              <span className="font-mono tabular-nums text-[#DFE2EF]">{targets.length}</span>{' '}
              monitored artifacts.
            </p>
          </div>
          <span className="font-mono text-[11px] uppercase tracking-[0.06em] text-[#87929A] tabular-nums">
            {targets.reduce((acc, t) => acc + t.packageCount, 0).toLocaleString()} packages indexed
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {severityTiles.map((tile) => (
            <button
              key={tile.id}
              type="button"
              onClick={() => onFilterBySeverity(tile.id)}
              className={`obsidian-card rounded-lg p-4 text-left hover:border-[#38BDF8]/50 transition-all cursor-pointer group ${tile.border}`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                  {tile.label}
                </span>
                <ArrowRight className="h-3.5 w-3.5 text-[#64748B] group-hover:text-[#38BDF8] transition-colors" />
              </div>
              <div
                className={`mt-2 font-display text-[32px] font-bold leading-none tabular-nums ${tile.accent}`}
              >
                {tile.count}
              </div>
              <div className="mt-2 font-mono text-[11px] text-[#94A3B8] truncate">{tile.sub}</div>
            </button>
          ))}
        </div>
      </section>

      {/* Section 2: Remediation Velocity Chart + Blast Radius Summary */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-7 obsidian-card rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="font-display text-[17px] font-semibold text-[#DFE2EF]">
                Exposure vs. Remediation Velocity
              </h2>
              <p className="text-[12px] text-[#94A3B8]">
                14-day window comparing open Critical/High CVEs against verified patch attestations.
              </p>
            </div>
            <div className="flex items-center gap-4 font-mono text-[11px]">
              <span className="flex items-center gap-1.5 text-[#F87171]">
                <span className="h-2 w-2 rounded-full bg-[#EF4444]" />
                Crit + High
              </span>
              <span className="flex items-center gap-1.5 text-[#34D399]">
                <span className="h-2 w-2 rounded-full bg-[#10B981]" />
                Remediated
              </span>
            </div>
          </div>

          <div className="relative w-full">
            <svg
              viewBox={`0 0 ${chartW} ${chartH}`}
              className="w-full h-[175px] overflow-visible"
              role="img"
              aria-label="Exposure vs remediation trend chart"
            >
              <defs>
                <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#EF4444" stopOpacity="0.24" />
                  <stop offset="100%" stopColor="#EF4444" stopOpacity="0" />
                </linearGradient>
                <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10B981" stopOpacity="0.20" />
                  <stop offset="100%" stopColor="#10B981" stopOpacity="0" />
                </linearGradient>
              </defs>

              {[0, 1, 2, 3].map((row) => {
                const y = padY + (row / 3) * (chartH - padY * 2);
                return (
                  <line
                    key={row}
                    x1={padX}
                    x2={chartW - padX}
                    y1={y}
                    y2={y}
                    stroke="#1E293B"
                    strokeDasharray="3 4"
                  />
                );
              })}

              {/* Area fills */}
              <path
                d={`${activeExposurePath} L ${toX(trend.length - 1)} ${chartH - padY} L ${toX(0)} ${chartH - padY} Z`}
                fill="url(#critGrad)"
              />
              <path
                d={`${remediatedPath} L ${toX(trend.length - 1)} ${chartH - padY} L ${toX(0)} ${chartH - padY} Z`}
                fill="url(#safeGrad)"
              />

              {/* Lines */}
              <path
                d={activeExposurePath}
                fill="none"
                stroke="#EF4444"
                strokeWidth="2"
                strokeLinecap="round"
              />
              <path
                d={remediatedPath}
                fill="none"
                stroke="#10B981"
                strokeWidth="2"
                strokeLinecap="round"
              />

              {/* Interactive points */}
              {trend.map((pt, i) => {
                const cx = toX(i);
                const cyOpen = toYOpen(pt.critical + pt.high);
                const cyRem = toYRem(pt.remediated);
                const isActive = i === hoveredIdx;
                return (
                  <g
                    key={pt.date}
                    onMouseEnter={() => setHoveredIdx(i)}
                    onClick={() => setHoveredIdx(i)}
                    className="cursor-pointer"
                  >
                    <rect
                      x={cx - 24}
                      y={0}
                      width={48}
                      height={chartH}
                      fill="transparent"
                    />
                    {isActive && (
                      <line
                        x1={cx}
                        x2={cx}
                        y1={padY}
                        y2={chartH - padY}
                        stroke="#38BDF8"
                        strokeOpacity="0.45"
                        strokeWidth="1"
                      />
                    )}
                    <circle
                      cx={cx}
                      cy={cyOpen}
                      r={isActive ? 4.5 : 3}
                      fill="#090D16"
                      stroke="#EF4444"
                      strokeWidth="2"
                    />
                    <circle
                      cx={cx}
                      cy={cyRem}
                      r={isActive ? 4.5 : 3}
                      fill="#090D16"
                      stroke="#10B981"
                      strokeWidth="2"
                    />
                    <text
                      x={cx}
                      y={chartH - 2}
                      textAnchor="middle"
                      fill={isActive ? '#8ED5FF' : '#64748B'}
                      fontSize="10"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {pt.date}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="pt-3 border-t border-[#1E293B] flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] tabular-nums">
            <span className="text-[#8ED5FF] font-semibold">Snapshot · {activePoint.date}</span>
            <div className="flex flex-wrap items-center gap-4 text-[#BDC8D1]">
              <span>
                Crit: <strong className="text-[#F87171]">{activePoint.critical}</strong>
              </span>
              <span>
                High: <strong className="text-[#FB923C]">{activePoint.high}</strong>
              </span>
              <span>
                Mod: <strong className="text-[#FBBF24]">{activePoint.moderate}</strong>
              </span>
              <span>
                Patched: <strong className="text-[#34D399]">{activePoint.remediated}</strong>
              </span>
            </div>
          </div>
        </div>

        {/* Artifact Verification Panel */}
        <div className="lg:col-span-5 obsidian-card rounded-lg p-5 flex flex-col justify-between gap-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-display text-[17px] font-semibold text-[#DFE2EF]">
                Scanning Targets
              </h2>
              <p className="text-[12px] text-[#94A3B8]">
                Container images &amp; lockfile manifests
              </p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('targets')}
              className="font-mono text-[11px] uppercase tracking-[0.06em] text-[#38BDF8] hover:text-[#8ED5FF] transition-colors cursor-pointer whitespace-nowrap"
            >
              Inspect All ›
            </button>
          </div>

          <div className="space-y-4">
            {/* Container Images group */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                <Container className="h-3.5 w-3.5 text-[#38BDF8]" />
                Container Images ({containerTargets.length})
              </div>
              {containerTargets.map((tgt) => {
                const openCount = vulnerabilities.filter(
                  (v) => v.targetId === tgt.id && v.status === 'open'
                ).length;
                return (
                  <div
                    key={tgt.id}
                    onClick={() => onNavigate('targets')}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && onNavigate('targets')}
                    className="rounded bg-[#090D16]/75 border border-[#1E293B] px-3 py-2.5 flex items-center justify-between gap-3 hover:border-[#38BDF8]/40 transition-colors cursor-pointer"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[12px] font-medium text-[#DFE2EF] truncate">
                          {tgt.name}
                        </span>
                        {tgt.signed ? (
                          <Lock className="h-3 w-3 text-[#10B981] shrink-0" aria-label="Signed" />
                        ) : (
                          <Unlock
                            className="h-3 w-3 text-[#F97316] shrink-0"
                            aria-label="Unsigned"
                          />
                        )}
                      </div>
                      <div className="font-mono text-[10px] text-[#64748B] truncate">
                        {tgt.digest.slice(0, 28)}...
                      </div>
                    </div>
                    <span
                      className={`font-mono text-[11px] font-semibold tabular-nums whitespace-nowrap shrink-0 ${
                        openCount > 0 ? 'text-[#F87171]' : 'text-[#34D399]'
                      }`}
                    >
                      {openCount > 0 ? `${openCount} open` : 'Clean'}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Lockfiles & Modules group */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                <FileCode2 className="h-3.5 w-3.5 text-[#6366F1]" />
                Lockfiles &amp; Modules ({lockfileTargets.length})
              </div>
              {lockfileTargets.slice(0, 3).map((tgt) => {
                const openCount = vulnerabilities.filter(
                  (v) => v.targetId === tgt.id && v.status === 'open'
                ).length;
                return (
                  <div
                    key={tgt.id}
                    onClick={() => onNavigate('targets')}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && onNavigate('targets')}
                    className="rounded bg-[#090D16]/75 border border-[#1E293B] px-3 py-2 flex items-center justify-between gap-3 hover:border-[#6366F1]/50 transition-colors cursor-pointer"
                  >
                    <div className="min-w-0 font-mono text-[12px] text-[#BDC8D1] truncate">
                      {tgt.name}
                    </div>
                    <span
                      className={`font-mono text-[11px] font-semibold tabular-nums whitespace-nowrap shrink-0 ${
                        openCount > 0 ? 'text-[#FB923C]' : 'text-[#34D399]'
                      }`}
                    >
                      {openCount > 0 ? `${openCount} open` : 'Clean'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      {/* Section 3: Prioritized CVE & Dependency Stream */}
      <section aria-label="Prioritized vulnerabilities" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            {counts.critical > 0 ? (
              <ShieldAlert className="h-5 w-5 text-[#EF4444]" />
            ) : (
              <ShieldCheck className="h-5 w-5 text-[#10B981]" />
            )}
            <div>
              <h2 className="font-display text-[20px] font-semibold tracking-[-0.015em] text-[#DFE2EF]">
                Prioritized CVE Advisories
              </h2>
              <p className="text-[13px] text-[#94A3B8]">
                Ordered by CVSS impact and active EPSS exploit probability. Select a card to open blast-radius diagnostics.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('advisories')}
            className="rounded border border-[#1E293B] bg-[#111827]/80 px-3.5 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#F8FAFC] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF] transition-colors whitespace-nowrap cursor-pointer"
          >
            View All ({vulnerabilities.length})
          </button>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3.5">
          {priorityVulns.map((vuln) => (
            <CveCard
              key={vuln.id}
              vuln={vuln}
              onSelect={onSelectVuln}
              onQuickPatch={onQuickPatch}
            />
          ))}
        </div>
      </section>
    </div>
  );
}
