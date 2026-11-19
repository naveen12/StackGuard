import { CheckCircle2, Download, ShieldCheck, Terminal, Wrench } from 'lucide-react';
import { Vulnerability } from '../types/security';
import { SeverityBadge } from './SeverityBadge';

interface RemediationViewProps {
  vulnerabilities: Vulnerability[];
  onPatch: (vulnId: string) => void;
  onPatchAllFixable: () => void;
  onSelectVuln: (vuln: Vulnerability) => void;
  onExportSbom: () => void;
}

export function RemediationView({
  vulnerabilities,
  onPatch,
  onPatchAllFixable,
  onSelectVuln,
  onExportSbom,
}: RemediationViewProps) {
  const openFixable = vulnerabilities.filter((v) => v.status === 'open' && v.fixedVersion);
  const patchedList = vulnerabilities.filter((v) => v.status === 'patched');

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-[24px] sm:text-[28px] font-semibold tracking-[-0.02em] text-[#DFE2EF]">
            Remediation &amp; Patch Queue
          </h1>
          <p className="text-[14px] text-[#94A3B8] mt-0.5">
            Review verified lockfile diffs, apply targeted upgrades, or export signed CycloneDX SBOM bundles.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={onExportSbom}
            className="inline-flex items-center gap-2 rounded border border-[#1E293B] bg-[#111827]/85 px-3.5 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#F8FAFC] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF] transition-colors whitespace-nowrap cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" />
            Export SBOM JSON
          </button>

          {openFixable.length > 0 && (
            <button
              type="button"
              onClick={onPatchAllFixable}
              className="inline-flex items-center gap-2 rounded bg-[#38BDF8] px-4 py-2 font-display text-[13px] font-semibold text-[#090D16] hover:bg-[#7BD0FF] active:scale-[0.98] glow-scanner transition-all whitespace-nowrap cursor-pointer"
            >
              <ShieldCheck className="h-4 w-4" />
              Apply All Patches ({openFixable.length})
            </button>
          )}
        </div>
      </div>

      {/* Pending Patch Queue */}
      <section className="space-y-3.5">
        <div className="flex items-center justify-between">
          <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
            Pending Upgrades ({openFixable.length})
          </h2>
        </div>

        {openFixable.length === 0 ? (
          <div className="obsidian-card rounded-lg p-10 text-center space-y-2.5 border-[#10B981]/35">
            <CheckCircle2 className="h-9 w-9 text-[#10B981] mx-auto" />
            <h3 className="font-display text-[18px] font-semibold text-[#DFE2EF]">
              Patch Queue Clear
            </h3>
            <p className="text-[13px] text-[#94A3B8] max-w-md mx-auto">
              Every fixable vulnerability across monitored container images and lockfiles has been patched and hash-verified.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {openFixable.map((vuln) => (
              <div
                key={vuln.id}
                className="obsidian-card rounded-lg p-5 space-y-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="font-mono text-[13px] font-semibold text-[#38BDF8]">
                        {vuln.cveId}
                      </span>
                      <SeverityBadge severity={vuln.severity} cvssScore={vuln.cvssScore} />
                      <span className="font-mono text-[12px] text-[#DFE2EF]">
                        {vuln.packageName}{' '}
                        <span className="text-[#F87171]">{vuln.installedVersion}</span>
                        <span className="text-[#87929A] mx-1.5">→</span>
                        <span className="text-[#34D399] font-semibold">{vuln.fixedVersion}</span>
                      </span>
                    </div>
                    <p className="text-[13px] text-[#94A3B8]">{vuln.title}</p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => onSelectVuln(vuln)}
                      className="rounded border border-[#1E293B] bg-[#090D16] px-3 py-1.5 font-mono text-[11px] text-[#BDC8D1] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF] transition-colors cursor-pointer whitespace-nowrap"
                    >
                      Inspect
                    </button>
                    <button
                      type="button"
                      onClick={() => onPatch(vuln.id)}
                      className="inline-flex items-center gap-1.5 rounded bg-[#38BDF8] px-3.5 py-1.5 font-display text-[12px] font-semibold text-[#090D16] hover:bg-[#7BD0FF] active:scale-[0.98] transition-all cursor-pointer whitespace-nowrap"
                    >
                      <Wrench className="h-3.5 w-3.5" />
                      Apply Fix
                    </button>
                  </div>
                </div>

                {/* Unified Diff Preview */}
                <div className="rounded bg-[#090D16] border border-[#1E293B] overflow-hidden font-mono text-[12px]">
                  <div className="px-3.5 py-1.5 border-b border-[#1E293B] flex items-center justify-between text-[10px] text-[#87929A] uppercase tracking-[0.06em]">
                    <span>{vuln.remediation.filePath}</span>
                    <span className="flex items-center gap-1 text-[#8ED5FF]">
                      <Terminal className="h-3 w-3" />
                      {vuln.remediation.command}
                    </span>
                  </div>
                  <div className="overflow-x-auto leading-6">
                    <div className="px-3.5 py-1 bg-[#EF4444]/10 text-[#F87171] whitespace-pre">
                      - {vuln.remediation.removedLine}
                    </div>
                    <div className="px-3.5 py-1 bg-[#10B981]/10 text-[#34D399] whitespace-pre">
                      + {vuln.remediation.addedLine}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Verified Remediations Log */}
      {patchedList.length > 0 && (
        <section className="space-y-3">
          <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
            Verified &amp; Remediated ({patchedList.length})
          </h2>
          <div className="obsidian-card rounded-lg divide-y divide-[#1E293B] overflow-hidden">
            {patchedList.map((v) => (
              <div
                key={v.id}
                onClick={() => onSelectVuln(v)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === 'Enter' && onSelectVuln(v)}
                className="px-4 py-3 flex flex-wrap items-center justify-between gap-3 hover:bg-[#182134]/70 transition-colors cursor-pointer"
              >
                <div className="flex flex-wrap items-center gap-3 font-mono text-[12px]">
                  <CheckCircle2 className="h-4 w-4 text-[#10B981] shrink-0" />
                  <span className="text-[#38BDF8] font-semibold">{v.cveId}</span>
                  <span className="text-[#DFE2EF]">
                    {v.packageName}@{v.fixedVersion ?? v.installedVersion}
                  </span>
                </div>
                <div className="flex items-center gap-3 font-mono text-[11px] text-[#94A3B8]">
                  <span className="hidden sm:inline truncate max-w-[240px]">{v.digest}</span>
                  <SeverityBadge severity="safe" compact />
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
