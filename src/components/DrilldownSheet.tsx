import { useState, useEffect } from 'react';
import {
  Check,
  CheckCircle2,
  ChevronRight,
  Code2,
  Copy,
  GitBranch,
  Layers,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  X,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Vulnerability } from '../types/security';
import { SeverityBadge } from './SeverityBadge';

interface DrilldownSheetProps {
  vuln: Vulnerability | null;
  onClose: () => void;
  onPatch: (vulnId: string) => void;
  onRevoke: (vulnId: string) => void;
}

type SheetTab = 'blast-radius' | 'remediation' | 'payload';

export function DrilldownSheet({ vuln, onClose, onPatch, onRevoke }: DrilldownSheetProps) {
  const [activeTab, setActiveTab] = useState<SheetTab>('blast-radius');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState(false);

  useEffect(() => {
    setConfirmRevoke(false);
    setCopiedKey(null);
  }, [vuln?.id]);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && vuln) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [vuln, onClose]);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  return (
    <AnimatePresence>
      {vuln && (
        <div
          className="fixed inset-0 z-50 flex items-end justify-center bg-[#090D16]/72 backdrop-blur-[4px]"
          onClick={onClose}
          role="dialog"
          aria-modal="true"
          aria-label={`Vulnerability details for ${vuln.cveId}`}
        >
          <motion.div
            initial={{ y: '100%', opacity: 0.6 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: '100%', opacity: 0.4 }}
            transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="obsidian-sheet w-full max-w-5xl rounded-t-xl max-h-[86vh] flex flex-col overflow-hidden"
          >
            {/* Pull Indicator: 36px wide, 4px high bar in #334155 */}
            <div className="flex justify-center pt-3 pb-1 shrink-0">
              <div className="h-[4px] w-[36px] rounded-full bg-[#334155]" />
            </div>

            {/* Header */}
            <div className="px-6 py-4 border-b border-[#334155]/45 flex flex-wrap items-start justify-between gap-4 shrink-0">
              <div className="min-w-0 flex-1 space-y-1.5">
                <div className="flex flex-wrap items-center gap-2.5">
                  <span className="font-mono text-[14px] font-semibold text-[#38BDF8]">
                    {vuln.cveId}
                  </span>
                  <SeverityBadge
                    severity={vuln.status === 'patched' ? 'safe' : vuln.severity}
                    cvssScore={vuln.cvssScore}
                  />
                  <span className="font-mono text-[12px] text-[#BDC8D1]">
                    {vuln.packageName}@{vuln.installedVersion}
                  </span>
                </div>
                <h2 className="font-display text-[19px] font-semibold text-[#DFE2EF] leading-snug">
                  {vuln.title}
                </h2>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-[#94A3B8]">
                  <span>{vuln.cvssVector}</span>
                  <span>·</span>
                  <span className="tabular-nums">EPSS {vuln.epssScore.toFixed(1)}%</span>
                  <span>·</span>
                  <span className="truncate max-w-[260px]">{vuln.digest}</span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {vuln.status === 'open' && vuln.fixedVersion && (
                  <button
                    type="button"
                    onClick={() => onPatch(vuln.id)}
                    className="inline-flex items-center gap-2 rounded bg-[#38BDF8] px-4 py-2 font-display text-[13px] font-semibold text-[#090D16] hover:bg-[#7BD0FF] active:scale-[0.98] glow-scanner transition-all whitespace-nowrap cursor-pointer"
                  >
                    <ShieldCheck className="h-4 w-4" />
                    Apply Patch ({vuln.fixedVersion})
                  </button>
                )}
                {vuln.status === 'patched' && (
                  <span className="inline-flex items-center gap-1.5 rounded border border-[#10B981]/40 bg-[#10B981]/12 px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#34D399]">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Remediated
                  </span>
                )}
                <button
                  type="button"
                  onClick={onClose}
                  aria-label="Close drill-down sheet"
                  className="inline-flex h-9 w-9 items-center justify-center rounded border border-[#334155]/60 bg-[#0F172A]/70 text-[#94A3B8] hover:text-[#DFE2EF] hover:border-[#38BDF8]/50 transition-colors cursor-pointer"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Segmented Tab Bar */}
            <div className="px-6 pt-3 pb-2 border-b border-[#334155]/35 flex items-center gap-2 overflow-x-auto shrink-0">
              {(
                [
                  { id: 'blast-radius', label: 'Blast Radius & Path Tree', icon: Layers },
                  { id: 'remediation', label: 'Remediation & Diff', icon: Terminal },
                  { id: 'payload', label: 'Raw JSON Payload', icon: Code2 },
                ] as const
              ).map((tab) => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id)}
                    className={`inline-flex items-center gap-2 rounded px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      active
                        ? 'bg-[#38BDF8]/15 text-[#8ED5FF] border border-[#38BDF8]/40'
                        : 'text-[#94A3B8] border border-transparent hover:text-[#DFE2EF] hover:bg-[#0F172A]/50'
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {tab.label}
                  </button>
                );
              })}
            </div>

            {/* Scrollable Body */}
            <div className="p-6 overflow-y-auto flex-1 space-y-6">
              {activeTab === 'blast-radius' && (
                <>
                  <div className="space-y-2">
                    <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                      Advisory Summary
                    </h3>
                    <p className="text-[14px] leading-[22px] text-[#BDC8D1]">{vuln.advisory}</p>
                  </div>

                  {/* Impacted Dependency & Blast-Radius Trees */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                        Blast-Radius Propagation Trees ({vuln.blastRadius.length})
                      </h3>
                      <span className="font-mono text-[11px] text-[#94A3B8]">
                        Target: {vuln.targetName}
                      </span>
                    </div>

                    <div className="space-y-3">
                      {vuln.blastRadius.map((br, idx) => (
                        <div
                          key={idx}
                          className="rounded-lg bg-[#090D16]/85 border border-[#1E293B] p-4 space-y-3"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <GitBranch className="h-4 w-4 text-[#6366F1]" />
                              <span className="font-mono text-[13px] font-medium text-[#DFE2EF]">
                                {br.serviceName}
                              </span>
                            </div>
                            <span
                              className={`rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] ${
                                br.exposure === 'internet-facing'
                                  ? 'border-[#EF4444]/40 bg-[#EF4444]/10 text-[#F87171]'
                                  : br.exposure === 'internal-mesh'
                                  ? 'border-[#F59E0B]/40 bg-[#F59E0B]/10 text-[#FBBF24]'
                                  : 'border-[#6366F1]/40 bg-[#6366F1]/10 text-[#C0C1FF]'
                              }`}
                            >
                              {br.exposure}
                            </span>
                          </div>

                          {/* Visual Hop Chain */}
                          <div className="flex flex-wrap items-center gap-2 pt-1">
                            <span className="rounded bg-[#181B25] border border-[#334155]/50 px-2.5 py-1 font-mono text-[11px] text-[#BDC8D1]">
                              {br.root}
                            </span>
                            {br.hops.map((hop, hopIdx) => {
                              const isLeaf = hopIdx === br.hops.length - 1;
                              return (
                                <div key={hopIdx} className="flex items-center gap-2">
                                  <ChevronRight className="h-3.5 w-3.5 text-[#6366F1]" />
                                  <span
                                    className={`rounded px-2.5 py-1 font-mono text-[11px] border ${
                                      isLeaf
                                        ? vuln.status === 'patched'
                                          ? 'bg-[#10B981]/12 border-[#10B981]/40 text-[#34D399]'
                                          : 'bg-[#EF4444]/12 border-[#EF4444]/40 text-[#F87171]'
                                        : 'bg-[#111827] border-[#1E293B] text-[#DFE2EF]'
                                    }`}
                                  >
                                    {hop}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}

              {activeTab === 'remediation' && (
                <div className="space-y-5">
                  {/* CLI Command Block */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                        Remediation Command
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy('cmd', vuln.remediation.command)}
                        className="inline-flex items-center gap-1.5 rounded border border-[#334155]/60 bg-[#090D16] px-2.5 py-1 font-mono text-[11px] text-[#BDC8D1] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF] transition-colors cursor-pointer"
                      >
                        {copiedKey === 'cmd' ? (
                          <>
                            <Check className="h-3 w-3 text-[#34D399]" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3" />
                            Copy
                          </>
                        )}
                      </button>
                    </div>
                    <div className="rounded bg-[#090D16] border border-[#1E293B] px-4 py-3 font-mono text-[13px] text-[#8ED5FF] overflow-x-auto">
                      <span className="text-[#6366F1] select-none mr-2">$</span>
                      {vuln.remediation.command}
                    </div>
                  </div>

                  {/* Manifest Diff */}
                  <div className="space-y-2">
                    <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                      Manifest Diff · {vuln.remediation.filePath}
                    </span>
                    <div className="rounded bg-[#090D16] border border-[#1E293B] overflow-x-auto font-mono text-[12px] leading-6">
                      <div className="px-4 py-1.5 bg-[#EF4444]/10 text-[#F87171] border-b border-[#1E293B]/60 whitespace-pre">
                        - {vuln.remediation.removedLine}
                      </div>
                      <div className="px-4 py-1.5 bg-[#10B981]/10 text-[#34D399] whitespace-pre">
                        + {vuln.remediation.addedLine}
                      </div>
                    </div>
                    <p className="text-[13px] text-[#94A3B8] pt-1">{vuln.remediation.notes}</p>
                  </div>

                  {/* Destructive Quarantine / Revoke Action */}
                  {vuln.status === 'open' && (
                    <div className="pt-4 border-t border-[#334155]/40 flex flex-wrap items-center justify-between gap-4">
                      <div className="flex items-start gap-2.5 max-w-lg">
                        <ShieldAlert className="h-4 w-4 text-[#EF4444] mt-0.5 shrink-0" />
                        <p className="text-[12px] text-[#94A3B8] leading-relaxed">
                          If upstream patch cannot be deployed immediately, revoke artifact signature and block cluster admission for this digest.
                        </p>
                      </div>
                      {!confirmRevoke ? (
                        <button
                          type="button"
                          onClick={() => setConfirmRevoke(true)}
                          className="inline-flex items-center gap-2 rounded border border-[#EF4444] bg-[#EF4444]/10 px-3.5 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#EF4444] hover:bg-[#EF4444]/20 active:scale-[0.98] transition-all cursor-pointer whitespace-nowrap"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          Revoke &amp; Quarantine
                        </button>
                      ) : (
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setConfirmRevoke(false)}
                            className="rounded border border-[#334155] bg-[#0F172A] px-3 py-1.5 font-mono text-[11px] text-[#BDC8D1] cursor-pointer"
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              onRevoke(vuln.id);
                              setConfirmRevoke(false);
                            }}
                            className="rounded bg-[#EF4444] px-3.5 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-white hover:bg-[#DC2626] cursor-pointer"
                          >
                            Confirm Revoke
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'payload' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                      Advisory &amp; Exploit Vector Payload (JSON)
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        handleCopy('json', JSON.stringify(vuln.exploitPayload, null, 2))
                      }
                      className="inline-flex items-center gap-1.5 rounded border border-[#334155]/60 bg-[#090D16] px-2.5 py-1 font-mono text-[11px] text-[#BDC8D1] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF] transition-colors cursor-pointer"
                    >
                      {copiedKey === 'json' ? (
                        <>
                          <Check className="h-3 w-3 text-[#34D399]" />
                          Copied JSON
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          Copy JSON
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="rounded-lg bg-[#090D16] border border-[#1E293B] p-4 font-mono text-[12px] leading-6 text-[#BDC8D1] overflow-x-auto">
                    {JSON.stringify(vuln.exploitPayload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
