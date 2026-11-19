import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Box,
  CheckCircle2,
  GitBranch,
  GitFork,
  Loader2,
  Radar,
  Shield,
  ShieldAlert,
  Upload,
  Wrench,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { AdvisoriesView } from './components/AdvisoriesView';
import { CommandTerminal } from './components/CommandTerminal';
import { DependencyGraphView } from './components/DependencyGraphView';
import { DrilldownSheet } from './components/DrilldownSheet';
import { RemediationView } from './components/RemediationView';
import { StackIntakeView } from './components/StackIntakeView';
import { TargetsView } from './components/TargetsView';
import { TelemetryOverview } from './components/TelemetryOverview';
import {
  BRANCHES,
  INITIAL_TARGETS,
  INITIAL_VULNERABILITIES,
  TELEMETRY_TREND,
} from './data/securityData';
import { ScanTarget, ScreenId, Severity, Vulnerability } from './types/security';

const SCREEN_META: Record<ScreenId, { label: string; shortLabel: string }> = {
  overview: { label: 'Telemetry Overview', shortLabel: 'Telemetry' },
  intake: { label: 'Feed Tech Stack', shortLabel: 'Feed Stack' },
  advisories: { label: 'CVE Advisories', shortLabel: 'Advisories' },
  graph: { label: 'Dependency Graph', shortLabel: 'Graph' },
  targets: { label: 'Scan Targets', shortLabel: 'Targets' },
  remediation: { label: 'Remediation Queue', shortLabel: 'Patch' },
};

export default function App() {
  const [activeScreen, setActiveScreen] = useState<ScreenId>('overview');
  const [selectedBranch, setSelectedBranch] = useState<string>(BRANCHES[0]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>(INITIAL_VULNERABILITIES);
  const [targets, setTargets] = useState<ScanTarget[]>(INITIAL_TARGETS);
  const [trend, setTrend] = useState(TELEMETRY_TREND);
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');

  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [toast, setToast] = useState<{ id: number; message: string; tone: 'cyan' | 'green' | 'red' } | null>(
    null
  );

  const showToast = useCallback((message: string, tone: 'cyan' | 'green' | 'red' = 'cyan') => {
    const id = Date.now() + Math.random();
    setToast({ id, message, tone });
    setTimeout(() => {
      setToast((prev) => (prev?.id === id ? null : prev));
    }, 3200);
  }, []);

  // Global Cmd+K / Ctrl+K shortcut for Query Terminal
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setTerminalOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const selectedVuln = useMemo(
    () => vulnerabilities.find((v) => v.id === selectedVulnId) ?? null,
    [vulnerabilities, selectedVulnId]
  );

  const openCount = useMemo(
    () => vulnerabilities.filter((v) => v.status === 'open').length,
    [vulnerabilities]
  );

  const criticalOpenCount = useMemo(
    () => vulnerabilities.filter((v) => v.status === 'open' && v.severity === 'critical').length,
    [vulnerabilities]
  );

  const fixableOpenCount = useMemo(
    () => vulnerabilities.filter((v) => v.status === 'open' && Boolean(v.fixedVersion)).length,
    [vulnerabilities]
  );

  const scanTimersRef = useRef<Array<ReturnType<typeof setTimeout>>>([]);

  useEffect(() => {
    return () => {
      scanTimersRef.current.forEach(clearTimeout);
    };
  }, []);

  const handleRunScan = useCallback(() => {
    if (isScanning) return;
    setIsScanning(true);
    setScanProgress(14);
    setTargets((prev) =>
      prev.map((t) => (t.status === 'revoked' ? t : { ...t, status: 'scanning' }))
    );

    scanTimersRef.current.forEach(clearTimeout);
    scanTimersRef.current = [];

    const step1 = setTimeout(() => setScanProgress(48), 450);
    const step2 = setTimeout(() => setScanProgress(82), 950);
    const step3 = setTimeout(() => {
      setScanProgress(100);
      setIsScanning(false);
      setTargets((prev) =>
        prev.map((t) =>
          t.status === 'revoked'
            ? t
            : { ...t, status: 'active', lastScanned: 'just now' }
        )
      );
      showToast(`Full SBOM & container scan completed on ${selectedBranch}.`, 'cyan');
    }, 1450);

    scanTimersRef.current.push(step1, step2, step3);
  }, [isScanning, selectedBranch, showToast]);

  const handlePatchVuln = useCallback(
    (vulnId: string) => {
      let patchedCve = '';
      setVulnerabilities((prev) =>
        prev.map((v) => {
          if (v.id !== vulnId) return v;
          patchedCve = `${v.cveId} (${v.packageName}@${v.fixedVersion ?? v.installedVersion})`;
          return {
            ...v,
            status: 'patched',
            installedVersion: v.fixedVersion ?? v.installedVersion,
            cvssVector: 'REMEDIATED · HASH VERIFIED',
            detectedAt: 'patched just now',
          };
        })
      );

      setTrend((prev) => {
        const next = [...prev];
        const last = next[next.length - 1];
        if (last) {
          next[next.length - 1] = {
            ...last,
            critical: Math.max(0, last.critical - 1),
            remediated: last.remediated + 1,
          };
        }
        return next;
      });

      if (patchedCve) {
        showToast(`Patched ${patchedCve} and verified digest.`, 'green');
      }
    },
    [showToast]
  );

  const handlePatchAllFixable = useCallback(() => {
    const count = vulnerabilities.filter((v) => v.status === 'open' && v.fixedVersion).length;
    if (count === 0) return;

    setVulnerabilities((prev) =>
      prev.map((v) =>
        v.status === 'open' && v.fixedVersion
          ? {
              ...v,
              status: 'patched',
              installedVersion: v.fixedVersion,
              cvssVector: 'REMEDIATED · HASH VERIFIED',
              detectedAt: 'patched just now',
            }
          : v
      )
    );
    setTrend((prev) => {
      const next = [...prev];
      const last = next[next.length - 1];
      if (last) {
        next[next.length - 1] = {
          ...last,
          critical: 0,
          high: 0,
          moderate: 0,
          remediated: last.remediated + count,
        };
      }
      return next;
    });
    showToast(`Applied ${count} verified lockfile & container patches.`, 'green');
  }, [vulnerabilities, showToast]);

  const handleRevokeVuln = useCallback(
    (vulnId: string) => {
      const target = vulnerabilities.find((v) => v.id === vulnId);
      setVulnerabilities((prev) =>
        prev.map((v) => (v.id === vulnId ? { ...v, status: 'revoked' } : v))
      );
      if (target) {
        setTargets((prev) =>
          prev.map((t) => (t.id === target.targetId ? { ...t, status: 'revoked' } : t))
        );
        showToast(`Quarantined digest for ${target.targetName} (${target.cveId}).`, 'red');
      }
      setSelectedVulnId(null);
    },
    [vulnerabilities, showToast]
  );

  const handleRescanTarget = useCallback(
    (targetId: string) => {
      const tgt = targets.find((t) => t.id === targetId);
      setTargets((prev) =>
        prev.map((t) => (t.id === targetId ? { ...t, status: 'scanning' } : t))
      );
      setTimeout(() => {
        setTargets((prev) =>
          prev.map((t) =>
            t.id === targetId ? { ...t, status: 'active', lastScanned: 'just now' } : t
          )
        );
        if (tgt) {
          showToast(`Re-verified layers & hashes for ${tgt.name}.`, 'cyan');
        }
      }, 900);
    },
    [targets, showToast]
  );

  const handleRevokeTarget = useCallback(
    (targetId: string) => {
      const tgt = targets.find((t) => t.id === targetId);
      setTargets((prev) =>
        prev.map((t) => (t.id === targetId ? { ...t, status: 'revoked' } : t))
      );
      if (tgt) {
        showToast(`Revoked admission signature for ${tgt.name}.`, 'red');
      }
    },
    [targets, showToast]
  );

  const handleExportSbom = useCallback(() => {
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      generatedAt: new Date().toISOString(),
      branch: selectedBranch,
      targets: targets.map((t) => ({
        name: t.name,
        reference: t.reference,
        digest: t.digest,
        signed: t.signed,
        provenance: t.provenance,
      })),
      vulnerabilities: vulnerabilities.map((v) => ({
        id: v.cveId,
        package: `${v.packageName}@${v.installedVersion}`,
        severity: v.severity,
        cvss: v.cvssScore,
        status: v.status,
        fixedVersion: v.fixedVersion,
      })),
    };
    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `stackguard-sbom-${selectedBranch.replace(/\//g, '-')}.json`;
    link.click();
    URL.revokeObjectURL(url);
    showToast('Exported CycloneDX SBOM JSON snapshot.', 'cyan');
  }, [selectedBranch, targets, vulnerabilities, showToast]);

  const handleStackScanned = useCallback(
    ({
      target,
      vulnerabilities: found,
      replaceWorkspace,
      liveOsvUsed,
    }: {
      target: ScanTarget;
      vulnerabilities: Vulnerability[];
      replaceWorkspace: boolean;
      liveOsvUsed: boolean;
    }) => {
      setTargets((prev) => (replaceWorkspace ? [target] : [target, ...prev]));
      setVulnerabilities((prev) => (replaceWorkspace ? found : [...found, ...prev]));
      setTrend((prev) => {
        const next = [...prev];
        const last = next[next.length - 1];
        if (last) {
          const addedCrit = found.filter((v) => v.severity === 'critical').length;
          const addedHigh = found.filter((v) => v.severity === 'high').length;
          const addedMod = found.filter((v) => v.severity === 'moderate').length;
          next[next.length - 1] = {
            ...last,
            critical: replaceWorkspace ? addedCrit : last.critical + addedCrit,
            high: replaceWorkspace ? addedHigh : last.high + addedHigh,
            moderate: replaceWorkspace ? addedMod : last.moderate + addedMod,
          };
        }
        return next;
      });
      showToast(
        `Scanned ${target.name}: ${found.length} CVE${found.length === 1 ? '' : 's'} found${
          liveOsvUsed ? ' (OSV.dev live)' : ''
        }.`,
        found.some((v) => v.severity === 'critical') ? 'red' : 'green'
      );
    },
    [showToast]
  );

  const handleFilterFromOverview = (sev: Severity) => {
    setSeverityFilter(sev);
    setActiveScreen('advisories');
  };

  const navItems: {
    id: ScreenId;
    label: string;
    shortLabel: string;
    icon: typeof Activity;
    badge?: number;
    badgeCritical?: boolean;
  }[] = [
    { id: 'overview', label: 'Telemetry', shortLabel: 'Telemetry', icon: Activity },
    { id: 'intake', label: 'Feed Tech Stack', shortLabel: 'Feed', icon: Upload },
    {
      id: 'advisories',
      label: 'CVE Advisories',
      shortLabel: 'CVEs',
      icon: ShieldAlert,
      badge: openCount,
      badgeCritical: criticalOpenCount > 0,
    },
    { id: 'graph', label: 'Blast Graph', shortLabel: 'Graph', icon: GitFork },
    {
      id: 'targets',
      label: 'Scan Targets',
      shortLabel: 'Targets',
      icon: Box,
      badge: targets.length,
    },
    {
      id: 'remediation',
      label: 'Remediation',
      shortLabel: 'Patch',
      icon: Wrench,
      badge: fixableOpenCount,
    },
  ];

  return (
    <div className="min-h-screen bg-[#090D16] obsidian-canvas-grid text-[#DFE2EF] flex">
      {/* Desktop Sidebar Navigation (248px fixed) */}
      <aside className="hidden lg:flex lg:flex-col lg:w-[248px] lg:shrink-0 border-r border-[#1E293B] bg-[#0A0E17]/95 backdrop-blur-md sticky top-0 h-screen">
        {/* Brand Header */}
        <div className="h-16 px-5 border-b border-[#1E293B] flex items-center gap-2.5 shrink-0">
          <div className="h-8 w-8 rounded bg-[#38BDF8]/12 border border-[#38BDF8]/40 flex items-center justify-center shrink-0">
            <Shield className="h-4.5 w-4.5 text-[#38BDF8]" />
          </div>
          <span className="font-display text-[16px] font-bold tracking-[-0.02em] text-[#DFE2EF] whitespace-nowrap">
            StackGuard
          </span>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Primary navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = activeScreen === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveScreen(item.id)}
                className={`w-full flex items-center justify-between gap-2.5 rounded px-3 py-2.5 text-left transition-colors cursor-pointer ${
                  active
                    ? 'bg-[#111827] text-[#8ED5FF] border border-[#38BDF8]/35'
                    : 'text-[#94A3B8] border border-transparent hover:text-[#DFE2EF] hover:bg-[#111827]/60'
                }`}
              >
                <span className="flex items-center gap-2.5 min-w-0">
                  <Icon
                    className={`h-4 w-4 shrink-0 ${
                      active ? 'text-[#38BDF8]' : 'text-[#64748B]'
                    }`}
                  />
                  <span className="font-display text-[13px] font-medium whitespace-nowrap truncate">
                    {item.label}
                  </span>
                </span>
                {typeof item.badge === 'number' && item.badge > 0 && (
                  <span
                    className={`min-w-[20px] h-5 px-1.5 rounded-full inline-flex items-center justify-center font-mono text-[10px] font-semibold tabular-nums ${
                      item.badgeCritical
                        ? 'bg-[#EF4444]/15 text-[#F87171] border border-[#EF4444]/40'
                        : 'bg-[#1E293B] text-[#BDC8D1]'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Active Scan Progress Drawer (only shown during real scan) */}
        <div className="p-4 border-t border-[#1E293B] space-y-3">
          {isScanning ? (
            <div className="rounded bg-[#111827] border border-[#38BDF8]/40 p-3 space-y-2 glow-scanner">
              <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.08em] text-[#8ED5FF]">
                <span className="flex items-center gap-1.5">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Scanning SBOMs
                </span>
                <span className="tabular-nums">{scanProgress}%</span>
              </div>
              <div className="h-1.5 w-full rounded bg-[#090D16] overflow-hidden">
                <div
                  className="h-full bg-[#38BDF8] transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>
          ) : (
            <div className="rounded bg-[#0F131C] border border-[#1E293B] p-3 space-y-1.5">
              <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.06em] text-[#87929A]">
                <span>Policy Gate</span>
                <span
                  className={
                    criticalOpenCount > 0
                      ? 'text-[#F87171] font-semibold'
                      : 'text-[#34D399] font-semibold'
                  }
                >
                  {criticalOpenCount > 0 ? 'BLOCKED' : 'PASSING'}
                </span>
              </div>
              <p className="font-mono text-[11px] text-[#94A3B8] tabular-nums">
                {criticalOpenCount > 0
                  ? `${criticalOpenCount} critical CVE${criticalOpenCount > 1 ? 's' : ''} blocking release`
                  : 'All release checks verified'}
              </p>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Shell */}
      <div className="flex-1 min-w-0 flex flex-col pb-20 lg:pb-0">
        {/* Top Navigation Bar */}
        <header className="sticky top-0 z-30 h-16 px-4 sm:px-6 border-b border-[#1E293B] bg-[#090D16]/88 backdrop-blur-md flex items-center justify-between gap-4">
          {/* Left: Mobile brand or Desktop Breadcrumb */}
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="lg:hidden h-7 w-7 rounded bg-[#38BDF8]/12 border border-[#38BDF8]/40 flex items-center justify-center shrink-0">
              <Shield className="h-4 w-4 text-[#38BDF8]" />
            </div>
            <div className="flex items-center gap-2 text-[13px] min-w-0">
              <span className="font-display font-semibold text-[#DFE2EF] lg:text-[#87929A] whitespace-nowrap">
                StackGuard
              </span>
              <span className="hidden sm:inline text-[#3E484F]" aria-hidden="true">
                /
              </span>
              <span className="hidden sm:inline font-display font-semibold text-[#DFE2EF] truncate">
                {SCREEN_META[activeScreen].label}
              </span>
            </div>
          </div>

          {/* Center: Query Terminal Trigger ($ ... Cmd+K) */}
          <button
            type="button"
            onClick={() => setTerminalOpen(true)}
            className="hidden md:flex items-center justify-between gap-4 w-full max-w-sm rounded border border-[#1E293B] bg-[#090D16] px-3 py-1.5 text-left hover:border-[#38BDF8]/50 transition-colors cursor-pointer"
          >
            <span className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-[12px] font-semibold text-[#38BDF8]">$</span>
              <span className="font-mono text-[12px] text-[#64748B] truncate">
                Query CVE, package, or sha256...
              </span>
            </span>
            <kbd className="rounded border border-[#334155] bg-[#111827] px-1.5 py-0.5 font-mono text-[10px] text-[#94A3B8] shrink-0">
              ⌘K
            </kbd>
          </button>

          {/* Right: Branch Select + Primary Scan Action */}
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="hidden sm:inline-flex items-center gap-1.5 rounded border border-[#1E293B] bg-[#111827]/80 px-2.5 py-1.5">
              <GitBranch className="h-3.5 w-3.5 text-[#6366F1] shrink-0" />
              <select
                value={selectedBranch}
                onChange={(e) => setSelectedBranch(e.target.value)}
                aria-label="Select Git branch"
                className="bg-transparent font-mono text-[12px] text-[#F8FAFC] focus:outline-none cursor-pointer"
              >
                {BRANCHES.map((b) => (
                  <option key={b} value={b} className="bg-[#0F131C]">
                    {b}
                  </option>
                ))}
              </select>
            </div>

            <button
              type="button"
              onClick={() => setActiveScreen('intake')}
              className={`hidden sm:inline-flex items-center gap-1.5 rounded border px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeScreen === 'intake'
                  ? 'border-[#38BDF8] bg-[#38BDF8]/15 text-[#8ED5FF]'
                  : 'border-[#1E293B] bg-[#111827]/80 text-[#DFE2EF] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF]'
              }`}
            >
              <Upload className="h-3.5 w-3.5 text-[#38BDF8]" />
              <span>Feed Stack</span>
            </button>

            <button
              type="button"
              onClick={handleRunScan}
              disabled={isScanning}
              className={`inline-flex items-center gap-2 rounded bg-[#38BDF8] px-3.5 py-2 font-display text-[13px] font-semibold text-[#090D16] hover:bg-[#7BD0FF] active:scale-[0.98] transition-all whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-80 ${
                isScanning ? 'glow-scanner' : ''
              }`}
            >
              {isScanning ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Radar className="h-4 w-4" />
              )}
              <span>{isScanning ? 'Scanning…' : 'Run Scan'}</span>
            </button>
          </div>
        </header>

        {/* Active Viewport */}
        <main className="flex-1 w-full max-w-[1360px] mx-auto px-4 sm:px-6 py-6 sm:py-8">
          {activeScreen === 'overview' && (
            <TelemetryOverview
              vulnerabilities={vulnerabilities}
              targets={targets}
              trend={trend}
              selectedBranch={selectedBranch}
              onSelectVuln={(v) => setSelectedVulnId(v.id)}
              onQuickPatch={handlePatchVuln}
              onFilterBySeverity={handleFilterFromOverview}
              onNavigate={setActiveScreen}
            />
          )}

          {activeScreen === 'intake' && (
            <StackIntakeView
              selectedBranch={selectedBranch}
              onStackScanned={handleStackScanned}
              onNavigate={setActiveScreen}
            />
          )}

          {activeScreen === 'advisories' && (
            <AdvisoriesView
              vulnerabilities={vulnerabilities}
              initialSeverity={severityFilter}
              onSeverityChange={setSeverityFilter}
              onSelectVuln={(v) => setSelectedVulnId(v.id)}
              onQuickPatch={handlePatchVuln}
            />
          )}

          {activeScreen === 'graph' && (
            <DependencyGraphView
              vulnerabilities={vulnerabilities}
              onSelectVuln={(v) => setSelectedVulnId(v.id)}
              onQuickPatch={handlePatchVuln}
            />
          )}

          {activeScreen === 'targets' && (
            <TargetsView
              targets={targets}
              vulnerabilities={vulnerabilities}
              onRescanTarget={handleRescanTarget}
              onRevokeTarget={handleRevokeTarget}
              onSelectVuln={(v) => setSelectedVulnId(v.id)}
              onFeedStack={() => setActiveScreen('intake')}
            />
          )}

          {activeScreen === 'remediation' && (
            <RemediationView
              vulnerabilities={vulnerabilities}
              onPatch={handlePatchVuln}
              onPatchAllFixable={handlePatchAllFixable}
              onSelectVuln={(v) => setSelectedVulnId(v.id)}
              onExportSbom={handleExportSbom}
            />
          )}
        </main>
      </div>

      {/* Mobile Bottom Navigation Bar (44px+ touch targets, compact height) */}
      <nav
        aria-label="Mobile navigation"
        className="lg:hidden fixed bottom-0 inset-x-0 z-30 border-t border-[#1E293B] bg-[#0A0E17]/95 backdrop-blur-md px-2 py-1.5 flex items-center justify-around"
      >
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = activeScreen === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveScreen(item.id)}
              className={`min-w-[54px] min-h-[44px] flex flex-col items-center justify-center gap-1 rounded px-2 transition-colors cursor-pointer ${
                active ? 'text-[#38BDF8]' : 'text-[#87929A]'
              }`}
            >
              <Icon className="h-4 w-4" />
              <span className="font-mono text-[9px] font-semibold uppercase tracking-[0.06em]">
                {item.shortLabel}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Elevated Bottom Sheet for CVE Drill-Down */}
      <DrilldownSheet
        vuln={selectedVuln}
        onClose={() => setSelectedVulnId(null)}
        onPatch={handlePatchVuln}
        onRevoke={handleRevokeVuln}
      />

      {/* Cmd+K Command Terminal Modal */}
      <CommandTerminal
        open={terminalOpen}
        onClose={() => setTerminalOpen(false)}
        vulnerabilities={vulnerabilities}
        targets={targets}
        onSelectVuln={(v) => setSelectedVulnId(v.id)}
        onNavigate={setActiveScreen}
        onRunScan={handleRunScan}
        onExportSbom={handleExportSbom}
      />

      {/* Action Confirmation Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 12 }}
            transition={{ duration: 0.18 }}
            className={`fixed bottom-20 lg:bottom-6 right-4 sm:right-6 z-40 obsidian-sheet rounded-lg px-4 py-3 flex items-center gap-2.5 max-w-md border ${
              toast.tone === 'green'
                ? 'border-[#10B981]/50'
                : toast.tone === 'red'
                ? 'border-[#EF4444]/50'
                : 'border-[#38BDF8]/50'
            }`}
          >
            <CheckCircle2
              className={`h-4 w-4 shrink-0 ${
                toast.tone === 'green'
                  ? 'text-[#34D399]'
                  : toast.tone === 'red'
                  ? 'text-[#F87171]'
                  : 'text-[#38BDF8]'
              }`}
            />
            <span className="font-mono text-[12px] text-[#DFE2EF]">{toast.message}</span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
