import { ArrowUpRight, CheckCircle2, Flame, FolderGit2, GitCommitHorizontal, ShieldCheck } from 'lucide-react';
import { Vulnerability } from '../types/security';
import { SEVERITY_STYLES, SeverityBadge } from './SeverityBadge';

interface CveCardProps {
  vuln: Vulnerability;
  selected?: boolean;
  onSelect: (vuln: Vulnerability) => void;
  onQuickPatch?: (vulnId: string) => void;
}

export function CveCard({ vuln, selected = false, onSelect, onQuickPatch }: CveCardProps) {
  const effectiveSeverity = vuln.status === 'patched' ? 'safe' : vuln.severity;
  const style = SEVERITY_STYLES[effectiveSeverity];
  const isCriticalOpen = effectiveSeverity === 'critical' && vuln.status === 'open';
  const repoPathDisplay = vuln.repositoryPath || vuln.remediation.filePath || vuln.targetName;

  return (
    <article
      onClick={() => onSelect(vuln)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(vuln);
        }
      }}
      className={`group relative overflow-hidden rounded-lg obsidian-card-interactive cursor-pointer text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#38BDF8] ${
        isCriticalOpen ? 'glow-critical border-[#EF4444]/35' : ''
      } ${selected ? 'border-[#38BDF8]/70 bg-[#182134]/95' : ''}`}
    >
      {/* 2px Left-edge status stripe per Obsidian Sentinel spec */}
      <span
        className={`absolute inset-y-0 left-0 w-[2px] ${style.stripe}`}
        aria-hidden="true"
      />

      <div className="p-4 pl-4.5 flex flex-col gap-2.5">
        {/* 1. Header Row: Monospaced package coordinate left; severity badge right */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex items-center gap-2">
            <span className="font-mono text-[13px] font-medium text-[#DFE2EF] truncate">
              {vuln.packageName}
              <span className="text-[#87929A]">@{vuln.installedVersion}</span>
            </span>
            {vuln.isKev && vuln.status === 'open' && (
              <span
                className="inline-flex items-center gap-1 rounded border border-[#EF4444]/40 bg-[#EF4444]/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.06em] text-[#F87171] whitespace-nowrap shrink-0"
                title="Listed in CISA Known Exploited Vulnerabilities Catalog"
              >
                <Flame className="h-2.5 w-2.5" />
                KEV
              </span>
            )}
          </div>
          <SeverityBadge severity={effectiveSeverity} cvssScore={vuln.cvssScore} />
        </div>

        {/* 2. Core Body: Single-line CVE ID in Cyan + Repository Path Tag */}
        <div className="flex flex-col gap-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-[12px] font-semibold tracking-[0.04em] text-[#38BDF8]">
                {vuln.cveId}
              </span>
              <span className="inline-flex items-center gap-1 rounded border border-[#334155]/60 bg-[#090D16] px-2 py-0.5 font-mono text-[10px] text-[#8ED5FF] truncate max-w-[220px]" title={`Repository Path: ${repoPathDisplay}`}>
                <FolderGit2 className="h-3 w-3 text-[#38BDF8] shrink-0" />
                <span className="truncate">{repoPathDisplay}</span>
              </span>
            </div>
            <span className="font-mono text-[10px] uppercase tracking-[0.06em] text-[#87929A] tabular-nums shrink-0">
              {vuln.branch} · {vuln.detectedAt}
            </span>
          </div>
          <p className="text-[13px] leading-[19px] text-[#94A3B8] line-clamp-2 mt-0.5">
            {vuln.advisory}
          </p>
        </div>

        {/* 3. Metadata Footer: Impacted path tree, fixed-in version badge, exploit likelihood */}
        <div className="pt-2.5 mt-0.5 border-t border-[#1E293B]/80 flex flex-wrap items-center justify-between gap-y-2 gap-x-3">
          <div className="min-w-0 flex items-center gap-1.5 text-[11px] font-mono text-[#87929A] truncate max-w-full sm:max-w-[55%]">
            <GitCommitHorizontal className="h-3.5 w-3.5 text-[#6366F1] shrink-0" />
            <span className="truncate">{vuln.impactedPath.join(' › ')}</span>
          </div>

          <div className="flex items-center gap-2.5 shrink-0 ml-auto">
            {vuln.status === 'patched' ? (
              <span className="inline-flex items-center gap-1 font-mono text-[11px] font-medium text-[#34D399]">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Verified {vuln.fixedVersion ?? vuln.installedVersion}
              </span>
            ) : vuln.fixedVersion ? (
              <span className="inline-flex items-center gap-1 rounded bg-[#10B981]/10 border border-[#10B981]/30 px-1.5 py-0.5 font-mono text-[11px] font-medium text-[#34D399] tabular-nums">
                Fix: {vuln.fixedVersion}
              </span>
            ) : (
              <span className="font-mono text-[11px] text-[#87929A]">No upstream patch</span>
            )}

            <span
              className="font-mono text-[11px] text-[#BDC8D1] tabular-nums"
              title="Exploit Prediction Scoring System (30-day exploitation probability)"
            >
              EPSS{' '}
              <span
                className={
                  vuln.epssScore >= 70
                    ? 'text-[#F87171] font-semibold'
                    : vuln.epssScore >= 30
                    ? 'text-[#FB923C] font-semibold'
                    : 'text-[#94A3B8]'
                }
              >
                {vuln.epssScore.toFixed(1)}%
              </span>
            </span>

            {onQuickPatch && vuln.status === 'open' && vuln.fixedVersion && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onQuickPatch(vuln.id);
                }}
                className="inline-flex items-center gap-1 rounded bg-[#38BDF8]/12 border border-[#38BDF8]/35 px-2 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.06em] text-[#8ED5FF] hover:bg-[#38BDF8] hover:text-[#090D16] active:scale-[0.98] transition-all whitespace-nowrap cursor-pointer"
              >
                <ShieldCheck className="h-3 w-3" />
                Patch
              </button>
            )}

            <ArrowUpRight className="h-3.5 w-3.5 text-[#87929A] group-hover:text-[#38BDF8] transition-colors shrink-0" />
          </div>
        </div>
      </div>
    </article>
  );
}
