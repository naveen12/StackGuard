import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowRight,
  Box,
  Download,
  GitBranch,
  Play,
  ShieldAlert,
  Terminal,
  X,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { ScanTarget, ScreenId, Vulnerability } from '../types/security';
import { SeverityBadge } from './SeverityBadge';

interface CommandTerminalProps {
  open: boolean;
  onClose: () => void;
  vulnerabilities: Vulnerability[];
  targets: ScanTarget[];
  onSelectVuln: (vuln: Vulnerability) => void;
  onNavigate: (screen: ScreenId) => void;
  onRunScan: () => void;
  onExportSbom: () => void;
}

export function CommandTerminal({
  open,
  onClose,
  vulnerabilities,
  targets,
  onSelectVuln,
  onNavigate,
  onRunScan,
  onExportSbom,
}: CommandTerminalProps) {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      setTimeout(() => inputRef.current?.focus(), 40);
    }
  }, [open]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open) {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  const normalized = query.trim().toLowerCase();

  const matchedVulns = useMemo(() => {
    if (!normalized) return vulnerabilities.slice(0, 4);
    return vulnerabilities
      .filter(
        (v) =>
          v.cveId.toLowerCase().includes(normalized) ||
          v.packageName.toLowerCase().includes(normalized) ||
          v.title.toLowerCase().includes(normalized) ||
          v.digest.toLowerCase().includes(normalized) ||
          v.severity.toLowerCase().includes(normalized)
      )
      .slice(0, 6);
  }, [vulnerabilities, normalized]);

  const matchedTargets = useMemo(() => {
    if (!normalized) return targets.slice(0, 3);
    return targets
      .filter(
        (t) =>
          t.name.toLowerCase().includes(normalized) ||
          t.reference.toLowerCase().includes(normalized) ||
          t.digest.toLowerCase().includes(normalized)
      )
      .slice(0, 4);
  }, [targets, normalized]);

  return (
    <AnimatePresence>
      {open && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] px-4 bg-[#090D16]/75 backdrop-blur-[6px]"
          onClick={onClose}
          role="dialog"
          aria-modal="true"
          aria-label="StackGuard Command Terminal"
        >
          <motion.div
            initial={{ opacity: 0, y: -12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="obsidian-sheet w-full max-w-2xl rounded-lg overflow-hidden"
          >
            {/* Inset Command Input */}
            <div className="p-3 border-b border-[#334155]/45 bg-[#090D16]/90">
              <div className="terminal-input flex items-center gap-2.5 rounded border border-[#1E293B] bg-[#090D16] px-3 py-2.5 transition-all">
                <span className="font-mono text-[14px] font-semibold text-[#38BDF8] select-none">
                  $
                </span>
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Query CVE-2024-21626, tar@6.1.11, sha256 digest, or target..."
                  className="w-full bg-transparent font-mono text-[13px] text-[#DFE2EF] placeholder:text-[#64748B] focus:outline-none"
                />
                {query && (
                  <button
                    type="button"
                    onClick={() => setQuery('')}
                    className="text-[#87929A] hover:text-[#DFE2EF] p-0.5 cursor-pointer"
                    aria-label="Clear query"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
                <kbd className="rounded border border-[#334155] bg-[#111827] px-1.5 py-0.5 font-mono text-[10px] text-[#94A3B8] shrink-0">
                  ESC
                </kbd>
              </div>
            </div>

            {/* Results */}
            <div className="max-h-[60vh] overflow-y-auto p-3 space-y-4">
              {/* Quick Commands */}
              <div className="space-y-1">
                <div className="px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                  Quick Commands
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      onNavigate('intake');
                      onClose();
                    }}
                    className="flex items-center gap-2 rounded border border-[#1E293B] bg-[#090D16]/70 px-3 py-2 text-left hover:border-[#38BDF8]/50 hover:bg-[#111827] transition-colors cursor-pointer"
                  >
                    <Play className="h-3.5 w-3.5 text-[#38BDF8]" />
                    <span className="font-mono text-[11px] text-[#DFE2EF]">feed --stack</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      onRunScan();
                      onClose();
                    }}
                    className="flex items-center gap-2 rounded border border-[#1E293B] bg-[#090D16]/70 px-3 py-2 text-left hover:border-[#38BDF8]/50 hover:bg-[#111827] transition-colors cursor-pointer"
                  >
                    <GitBranch className="h-3.5 w-3.5 text-[#6366F1]" />
                    <span className="font-mono text-[11px] text-[#DFE2EF]">scan --all</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      onExportSbom();
                      onClose();
                    }}
                    className="flex items-center gap-2 rounded border border-[#1E293B] bg-[#090D16]/70 px-3 py-2 text-left hover:border-[#38BDF8]/50 hover:bg-[#111827] transition-colors cursor-pointer"
                  >
                    <Download className="h-3.5 w-3.5 text-[#10B981]" />
                    <span className="font-mono text-[11px] text-[#DFE2EF]">export --sbom</span>
                  </button>
                </div>
              </div>

              {/* Matching CVEs */}
              <div className="space-y-1">
                <div className="px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                  CVE Advisories ({matchedVulns.length})
                </div>
                {matchedVulns.length === 0 ? (
                  <div className="rounded border border-[#1E293B] bg-[#090D16]/50 px-3 py-4 text-center font-mono text-[12px] text-[#87929A]">
                    No advisories match &ldquo;{query}&rdquo;
                  </div>
                ) : (
                  <div className="space-y-1">
                    {matchedVulns.map((v) => (
                      <button
                        key={v.id}
                        type="button"
                        onClick={() => {
                          onSelectVuln(v);
                          onClose();
                        }}
                        className="w-full flex items-center justify-between gap-3 rounded px-2.5 py-2 text-left hover:bg-[#090D16]/75 border border-transparent hover:border-[#38BDF8]/30 transition-colors cursor-pointer"
                      >
                        <div className="min-w-0 flex items-center gap-2.5">
                          <ShieldAlert className="h-4 w-4 text-[#38BDF8] shrink-0" />
                          <div className="min-w-0">
                            <div className="flex items-center gap-2 font-mono text-[12px]">
                              <span className="text-[#38BDF8] font-semibold">{v.cveId}</span>
                              <span className="text-[#DFE2EF] truncate">
                                {v.packageName}@{v.installedVersion}
                              </span>
                            </div>
                            <p className="text-[12px] text-[#94A3B8] truncate">{v.title}</p>
                          </div>
                        </div>
                        <SeverityBadge
                          severity={v.status === 'patched' ? 'safe' : v.severity}
                          cvssScore={v.cvssScore}
                          compact
                        />
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Matching Scan Targets */}
              {matchedTargets.length > 0 && (
                <div className="space-y-1">
                  <div className="px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                    Scanning Targets ({matchedTargets.length})
                  </div>
                  <div className="space-y-1">
                    {matchedTargets.map((t) => (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => {
                          onNavigate('targets');
                          onClose();
                        }}
                        className="w-full flex items-center justify-between gap-3 rounded px-2.5 py-2 text-left hover:bg-[#090D16]/75 border border-transparent hover:border-[#6366F1]/40 transition-colors cursor-pointer"
                      >
                        <div className="min-w-0 flex items-center gap-2.5">
                          <Box className="h-4 w-4 text-[#6366F1] shrink-0" />
                          <div className="min-w-0">
                            <div className="font-mono text-[12px] text-[#DFE2EF] truncate">
                              {t.name}
                            </div>
                            <div className="font-mono text-[11px] text-[#87929A] truncate">
                              {t.digest.slice(0, 34)}...
                            </div>
                          </div>
                        </div>
                        <ArrowRight className="h-3.5 w-3.5 text-[#87929A] shrink-0" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="px-4 py-2 border-t border-[#334155]/40 bg-[#090D16]/80 flex items-center justify-between font-mono text-[10px] text-[#87929A]">
              <span className="flex items-center gap-1.5">
                <Terminal className="h-3 w-3 text-[#38BDF8]" />
                StackGuard Query Shell
              </span>
              <span>Click any item to inspect</span>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
