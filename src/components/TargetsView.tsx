import { useState } from 'react';
import {
  Container,
  FileCode2,
  Lock,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Unlock,
} from 'lucide-react';
import { ScanTarget, Vulnerability } from '../types/security';

interface TargetsViewProps {
  targets: ScanTarget[];
  vulnerabilities: Vulnerability[];
  onRescanTarget: (targetId: string) => void;
  onRevokeTarget: (targetId: string) => void;
  onSelectVuln: (vuln: Vulnerability) => void;
  onFeedStack: () => void;
}

export function TargetsView({
  targets,
  vulnerabilities,
  onRescanTarget,
  onRevokeTarget,
  onSelectVuln,
  onFeedStack,
}: TargetsViewProps) {
  const [confirmPurgeId, setConfirmPurgeId] = useState<string | null>(null);

  const containers = targets.filter((t) => t.category === 'container');
  const lockfiles = targets.filter((t) => t.category !== 'container');

  const renderTargetCard = (target: ScanTarget) => {
    const related = vulnerabilities.filter((v) => v.targetId === target.id);
    const openCrit = related.filter((v) => v.status === 'open' && v.severity === 'critical').length;
    const openHigh = related.filter((v) => v.status === 'open' && v.severity === 'high').length;
    const openMod = related.filter((v) => v.status === 'open' && v.severity === 'moderate').length;
    const isScanning = target.status === 'scanning';
    const isRevoked = target.status === 'revoked';

    return (
      <div
        key={target.id}
        className={`obsidian-card rounded-lg p-5 flex flex-col justify-between gap-4 transition-all ${
          isScanning ? 'glow-scanner border-[#38BDF8]/60' : ''
        } ${isRevoked ? 'opacity-65 border-[#EF4444]/40' : ''}`}
      >
        <div className="space-y-2.5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="font-mono text-[14px] font-semibold text-[#DFE2EF] truncate">
                  {target.name}
                </h3>
                {isRevoked && (
                  <span className="rounded border border-[#EF4444]/40 bg-[#EF4444]/12 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.06em] text-[#F87171]">
                    REVOKED
                  </span>
                )}
              </div>
              <p className="font-mono text-[11px] text-[#87929A] truncate mt-0.5">
                {target.reference}
              </p>
            </div>

            <span
              className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.06em] whitespace-nowrap shrink-0 ${
                target.signed
                  ? 'border-[#10B981]/35 bg-[#10B981]/10 text-[#34D399]'
                  : 'border-[#F97316]/40 bg-[#F97316]/10 text-[#FB923C]'
              }`}
            >
              {target.signed ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
              {target.signed ? 'Signed' : 'Unsigned'}
            </span>
          </div>

          {/* Checksum & Provenance */}
          <div className="rounded bg-[#090D16]/85 border border-[#1E293B] px-3 py-2 font-mono text-[11px] space-y-1">
            <div className="text-[#8ED5FF] truncate" title={target.digest}>
              {target.digest}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-[#87929A] text-[10px] uppercase tracking-[0.06em]">
              <span>{target.provenance}</span>
              <span className="tabular-nums">
                {target.packageCount} pkgs {target.layers ? `· ${target.layers} layers` : ''}
              </span>
            </div>
          </div>

          {/* Severity Distribution Strip */}
          <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] tabular-nums pt-0.5">
            {openCrit === 0 && openHigh === 0 && openMod === 0 ? (
              <span className="inline-flex items-center gap-1.5 text-[#34D399]">
                <ShieldCheck className="h-3.5 w-3.5" />
                Zero high-severity CVEs active
              </span>
            ) : (
              <>
                <span className={openCrit > 0 ? 'text-[#F87171] font-semibold' : 'text-[#64748B]'}>
                  {openCrit} CRIT
                </span>
                <span className="text-[#334155]">/</span>
                <span className={openHigh > 0 ? 'text-[#FB923C] font-semibold' : 'text-[#64748B]'}>
                  {openHigh} HIGH
                </span>
                <span className="text-[#334155]">/</span>
                <span className={openMod > 0 ? 'text-[#FBBF24] font-semibold' : 'text-[#64748B]'}>
                  {openMod} MOD
                </span>
              </>
            )}
            <span className="ml-auto text-[10px] uppercase tracking-[0.06em] text-[#87929A]">
              {target.branch} · {target.lastScanned}
            </span>
          </div>
        </div>

        {/* Linked CVEs quick pills + Actions */}
        <div className="pt-3 border-t border-[#1E293B] flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {related.slice(0, 2).map((v) => (
              <button
                key={v.id}
                type="button"
                onClick={() => onSelectVuln(v)}
                className="rounded border border-[#334155]/60 bg-[#090D16] px-2 py-1 font-mono text-[10px] text-[#38BDF8] hover:border-[#38BDF8] transition-colors cursor-pointer"
              >
                {v.cveId}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 ml-auto">
            <button
              type="button"
              disabled={isScanning || isRevoked}
              onClick={() => onRescanTarget(target.id)}
              className="inline-flex items-center gap-1.5 rounded border border-[#1E293B] bg-[#111827] px-3 py-1.5 font-mono text-[11px] font-medium text-[#F8FAFC] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF] disabled:opacity-40 transition-colors cursor-pointer whitespace-nowrap"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isScanning ? 'animate-spin text-[#38BDF8]' : ''}`} />
              {isScanning ? 'Scanning…' : 'Re-scan'}
            </button>

            {!isRevoked &&
              (confirmPurgeId === target.id ? (
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setConfirmPurgeId(null)}
                    className="rounded border border-[#334155] px-2 py-1.5 font-mono text-[10px] text-[#94A3B8] cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      onRevokeTarget(target.id);
                      setConfirmPurgeId(null);
                    }}
                    className="rounded bg-[#EF4444] px-2.5 py-1.5 font-mono text-[10px] font-semibold uppercase text-white cursor-pointer"
                  >
                    Purge
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmPurgeId(target.id)}
                  className="inline-flex items-center gap-1.5 rounded border border-[#EF4444] bg-[#EF4444]/10 px-2.5 py-1.5 font-mono text-[11px] font-semibold text-[#EF4444] hover:bg-[#EF4444]/20 transition-colors cursor-pointer whitespace-nowrap"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Revoke
                </button>
              ))}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-[24px] sm:text-[28px] font-semibold tracking-[-0.02em] text-[#DFE2EF]">
            Scanning Targets &amp; Artifact Digests
          </h1>
          <p className="text-[14px] text-[#94A3B8] mt-0.5">
            Cryptographic SHA-256 verification, SLSA provenance checks, and container admission controls.
          </p>
        </div>
        <button
          type="button"
          onClick={onFeedStack}
          className="inline-flex items-center gap-2 rounded bg-[#38BDF8] px-4 py-2 font-display text-[13px] font-semibold text-[#090D16] hover:bg-[#7BD0FF] active:scale-[0.98] transition-all cursor-pointer whitespace-nowrap"
        >
          <Plus className="h-4 w-4" />
          Feed Tech Stack
        </button>
      </div>

      {/* Container Images Section (isolated with space-xl / 2rem spacing) */}
      <section className="space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-2.5">
          <div className="flex items-center gap-2">
            <Container className="h-4.5 w-4.5 text-[#38BDF8]" />
            <h2 className="font-display text-[18px] font-semibold text-[#DFE2EF]">
              Container Images
            </h2>
          </div>
          <span className="font-mono text-[11px] uppercase tracking-[0.06em] text-[#87929A] tabular-nums">
            {containers.length} OCI Registries
          </span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {containers.map(renderTargetCard)}
        </div>
      </section>

      {/* Lockfiles & Dependency Manifests Section */}
      <section className="space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-2.5">
          <div className="flex items-center gap-2">
            <FileCode2 className="h-4.5 w-4.5 text-[#6366F1]" />
            <h2 className="font-display text-[18px] font-semibold text-[#DFE2EF]">
              Node.js Lockfiles, Go Modules &amp; Python Wheels
            </h2>
          </div>
          <span className="font-mono text-[11px] uppercase tracking-[0.06em] text-[#87929A] tabular-nums">
            {lockfiles.length} SBOM Manifests
          </span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {lockfiles.map(renderTargetCard)}
        </div>
      </section>
    </div>
  );
}
