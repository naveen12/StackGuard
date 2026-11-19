import { useMemo, useState } from 'react';
import { ArrowUpRight, Filter, GitFork, Layers, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Vulnerability } from '../types/security';
import { SEVERITY_STYLES, SeverityBadge } from './SeverityBadge';

interface DependencyGraphViewProps {
  vulnerabilities: Vulnerability[];
  onSelectVuln: (vuln: Vulnerability) => void;
  onQuickPatch: (vulnId: string) => void;
}

export function DependencyGraphView({
  vulnerabilities,
  onSelectVuln,
  onQuickPatch,
}: DependencyGraphViewProps) {
  const [openOnly, setOpenOnly] = useState(true);
  const [focusedId, setFocusedId] = useState<string>(vulnerabilities[0]?.id ?? '');

  const visibleVulns = useMemo(() => {
    const list = openOnly
      ? vulnerabilities.filter((v) => v.status === 'open')
      : vulnerabilities;
    return list.slice(0, 6);
  }, [vulnerabilities, openOnly]);

  const focusedVuln =
    visibleVulns.find((v) => v.id === focusedId) ?? visibleVulns[0] ?? vulnerabilities[0];

  // Build 3-column SVG topology for the visible vulnerabilities
  const roots = useMemo(() => {
    const map = new Map<string, { label: string; vulnIds: string[] }>();
    visibleVulns.forEach((v) => {
      const rootLabel = v.impactedPath[0] ?? v.targetName;
      const existing = map.get(rootLabel);
      if (existing) {
        existing.vulnIds.push(v.id);
      } else {
        map.set(rootLabel, { label: rootLabel, vulnIds: [v.id] });
      }
    });
    return Array.from(map.values());
  }, [visibleVulns]);

  const intermediates = useMemo(() => {
    return visibleVulns.map((v) => ({
      id: `mid-${v.id}`,
      vulnId: v.id,
      rootLabel: v.impactedPath[0] ?? v.targetName,
      label: v.impactedPath[1] ?? `${v.packageName}@${v.installedVersion}`,
    }));
  }, [visibleVulns]);

  const svgW = 920;
  const svgH = Math.max(360, visibleVulns.length * 76 + 40);

  const rootPositions = roots.map((r, i) => ({
    ...r,
    x: 24,
    y: 36 + (i * (svgH - 80)) / Math.max(roots.length - 1, 1) - (roots.length === 1 ? 0 : 0),
  }));

  const getRootPos = (label: string) =>
    rootPositions.find((r) => r.label === label) ?? { x: 24, y: svgH / 2 };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-[24px] sm:text-[28px] font-semibold tracking-[-0.02em] text-[#DFE2EF]">
            Dependency Graph &amp; Blast Radius
          </h1>
          <p className="text-[14px] text-[#94A3B8] mt-0.5">
            Trace transitive supply-chain paths from runtime artifacts to vulnerable leaf packages.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setOpenOnly((p) => !p)}
            className={`inline-flex items-center gap-2 rounded border px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] transition-colors cursor-pointer whitespace-nowrap ${
              openOnly
                ? 'border-[#38BDF8]/50 bg-[#38BDF8]/12 text-[#8ED5FF]'
                : 'border-[#1E293B] bg-[#111827] text-[#94A3B8] hover:text-[#DFE2EF]'
            }`}
          >
            <Filter className="h-3.5 w-3.5" />
            {openOnly ? 'Open Exposures Only' : 'Showing All Paths'}
          </button>
        </div>
      </div>

      {/* Interactive SVG Topology Canvas */}
      <div className="obsidian-card rounded-lg overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1E293B] bg-[#090D16]/70 flex flex-wrap items-center justify-between gap-3 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
          <div className="flex items-center gap-6">
            <span className="text-[#8ED5FF]">01 · Entry Artifact</span>
            <span className="text-[#C0C1FF]">02 · Intermediate / Runtime Shim</span>
            <span className="text-[#F87171]">03 · Vulnerable Leaf &amp; CVE</span>
          </div>
          <span className="text-[#94A3B8]">Click any node to isolate blast path</span>
        </div>

        {visibleVulns.length === 0 ? (
          <div className="p-12 text-center space-y-2">
            <ShieldCheck className="h-8 w-8 text-[#10B981] mx-auto" />
            <p className="font-display text-[16px] font-semibold text-[#DFE2EF]">
              Zero Open Blast Paths
            </p>
            <p className="text-[13px] text-[#94A3B8]">
              All tracked vulnerabilities have been remediated. Toggle &ldquo;Showing All Paths&rdquo; to inspect verified chains.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto p-4 bg-[#090D16]/45">
            <svg
              viewBox={`0 0 ${svgW} ${svgH}`}
              className="w-full min-w-[740px] h-auto"
              role="img"
              aria-label="Supply chain dependency graph"
            >
              {/* Edges: Root -> Intermediate -> Leaf */}
              {visibleVulns.map((v, idx) => {
                const mid = intermediates[idx];
                const root = getRootPos(mid.rootLabel);
                const rowY = 38 + idx * 72;
                const isFocused = focusedVuln?.id === v.id;
                const effSev = v.status === 'patched' ? 'safe' : v.severity;
                const strokeColor =
                  effSev === 'critical'
                    ? '#EF4444'
                    : effSev === 'high'
                    ? '#F97316'
                    : effSev === 'safe'
                    ? '#10B981'
                    : '#6366F1';

                const x1 = root.x + 210;
                const y1 = root.y + 22;
                const x2 = 345;
                const y2 = rowY + 22;
                const x3 = 565;
                const x4 = 640;

                return (
                  <g key={`edges-${v.id}`}>
                    <path
                      d={`M ${x1} ${y1} C ${x1 + 55} ${y1}, ${x2 - 55} ${y2}, ${x2} ${y2}`}
                      fill="none"
                      stroke={isFocused ? '#38BDF8' : '#334155'}
                      strokeOpacity={isFocused ? 0.9 : 0.45}
                      strokeWidth={isFocused ? 2.2 : 1.2}
                    />
                    <path
                      d={`M ${x3} ${y2} C ${x3 + 35} ${y2}, ${x4 - 35} ${y2}, ${x4} ${y2}`}
                      fill="none"
                      stroke={isFocused ? strokeColor : '#334155'}
                      strokeOpacity={isFocused ? 0.95 : 0.45}
                      strokeWidth={isFocused ? 2.4 : 1.2}
                    />
                  </g>
                );
              })}

              {/* Tier 1: Root Artifact Nodes */}
              {rootPositions.map((r) => {
                const isFocused = focusedVuln && r.vulnIds.includes(focusedVuln.id);
                return (
                  <g
                    key={r.label}
                    transform={`translate(${r.x}, ${r.y})`}
                    onClick={() => setFocusedId(r.vulnIds[0])}
                    className="cursor-pointer"
                  >
                    <rect
                      width="210"
                      height="44"
                      rx="6"
                      fill="#111827"
                      stroke={isFocused ? '#38BDF8' : '#1E293B'}
                      strokeWidth={isFocused ? 1.5 : 1}
                    />
                    <text
                      x="12"
                      y="18"
                      fill="#87929A"
                      fontSize="9"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      ROOT ARTIFACT
                    </text>
                    <text
                      x="12"
                      y="33"
                      fill="#DFE2EF"
                      fontSize="11"
                      fontWeight="600"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {r.label.length > 24 ? `${r.label.slice(0, 23)}…` : r.label}
                    </text>
                  </g>
                );
              })}

              {/* Tier 2: Intermediate Dependency Nodes */}
              {intermediates.map((mid, idx) => {
                const rowY = 38 + idx * 72;
                const isFocused = focusedVuln?.id === mid.vulnId;
                return (
                  <g
                    key={mid.id}
                    transform={`translate(345, ${rowY})`}
                    onClick={() => setFocusedId(mid.vulnId)}
                    className="cursor-pointer"
                  >
                    <rect
                      width="220"
                      height="44"
                      rx="6"
                      fill={isFocused ? '#172033' : '#111827'}
                      stroke={isFocused ? '#6366F1' : '#1E293B'}
                      strokeWidth={isFocused ? 1.5 : 1}
                    />
                    <text
                      x="12"
                      y="18"
                      fill="#C0C1FF"
                      fontSize="9"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      TRANSITIVE HOP
                    </text>
                    <text
                      x="12"
                      y="33"
                      fill="#DFE2EF"
                      fontSize="11"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {mid.label.length > 26 ? `${mid.label.slice(0, 25)}…` : mid.label}
                    </text>
                  </g>
                );
              })}

              {/* Tier 3: Vulnerable Leaf Nodes */}
              {visibleVulns.map((v, idx) => {
                const rowY = 38 + idx * 72;
                const isFocused = focusedVuln?.id === v.id;
                const effSev = v.status === 'patched' ? 'safe' : v.severity;
                const borderHex =
                  effSev === 'critical'
                    ? '#EF4444'
                    : effSev === 'high'
                    ? '#F97316'
                    : effSev === 'moderate'
                    ? '#F59E0B'
                    : effSev === 'safe'
                    ? '#10B981'
                    : '#64748B';

                return (
                  <g
                    key={`leaf-${v.id}`}
                    transform={`translate(640, ${rowY})`}
                    onClick={() => setFocusedId(v.id)}
                    className="cursor-pointer"
                  >
                    <rect
                      width="256"
                      height="44"
                      rx="6"
                      fill={isFocused ? '#1A1F2E' : '#111827'}
                      stroke={borderHex}
                      strokeOpacity={isFocused ? 1 : 0.45}
                      strokeWidth={isFocused ? 1.8 : 1}
                    />
                    <rect width="3" height="44" rx="1" fill={borderHex} />
                    <text
                      x="14"
                      y="18"
                      fill="#38BDF8"
                      fontSize="10"
                      fontWeight="600"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {v.cveId} · CVSS {v.cvssScore.toFixed(1)}
                    </text>
                    <text
                      x="14"
                      y="34"
                      fill="#DFE2EF"
                      fontSize="11"
                      fontWeight="500"
                      fontFamily="JetBrains Mono, monospace"
                    >
                      {`${v.packageName}@${v.installedVersion}`.slice(0, 29)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
      </div>

      {/* Selected Node Blast-Radius Diagnostic Inspector */}
      {focusedVuln && (
        <div
          className={`obsidian-card rounded-lg p-5 relative overflow-hidden ${
            focusedVuln.severity === 'critical' && focusedVuln.status === 'open'
              ? 'glow-critical border-[#EF4444]/40'
              : ''
          }`}
        >
          <span
            className={`absolute inset-y-0 left-0 w-[2px] ${
              SEVERITY_STYLES[focusedVuln.status === 'patched' ? 'safe' : focusedVuln.severity]
                .stripe
            }`}
          />
          <div className="pl-2 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-2 max-w-2xl">
              <div className="flex flex-wrap items-center gap-2.5">
                <GitFork className="h-4 w-4 text-[#6366F1]" />
                <span className="font-mono text-[13px] font-semibold text-[#38BDF8]">
                  {focusedVuln.cveId}
                </span>
                <SeverityBadge
                  severity={focusedVuln.status === 'patched' ? 'safe' : focusedVuln.severity}
                  cvssScore={focusedVuln.cvssScore}
                />
                <span className="font-mono text-[12px] text-[#DFE2EF]">
                  {focusedVuln.packageName}@{focusedVuln.installedVersion}
                </span>
              </div>
              <h2 className="font-display text-[17px] font-semibold text-[#DFE2EF]">
                {focusedVuln.title}
              </h2>
              <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-[#94A3B8]">
                <span className="inline-flex items-center gap-1">
                  <Layers className="h-3.5 w-3.5 text-[#6366F1]" />
                  {focusedVuln.blastRadius.length} production service
                  {focusedVuln.blastRadius.length > 1 ? 's' : ''} impacted
                </span>
                <span>·</span>
                <span>
                  Services:{' '}
                  <strong className="text-[#DFE2EF]">
                    {focusedVuln.blastRadius.map((b) => b.serviceName).join(', ')}
                  </strong>
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              {focusedVuln.status === 'open' && focusedVuln.fixedVersion && (
                <button
                  type="button"
                  onClick={() => onQuickPatch(focusedVuln.id)}
                  className="inline-flex items-center gap-2 rounded bg-[#38BDF8] px-4 py-2 font-display text-[13px] font-semibold text-[#090D16] hover:bg-[#7BD0FF] active:scale-[0.98] transition-all cursor-pointer whitespace-nowrap"
                >
                  <ShieldCheck className="h-4 w-4" />
                  Upgrade to {focusedVuln.fixedVersion}
                </button>
              )}
              <button
                type="button"
                onClick={() => onSelectVuln(focusedVuln)}
                className="inline-flex items-center gap-1.5 rounded border border-[#1E293B] bg-[#090D16] px-3.5 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#DFE2EF] hover:border-[#38BDF8]/50 hover:text-[#8ED5FF] transition-colors cursor-pointer whitespace-nowrap"
              >
                <ShieldAlert className="h-3.5 w-3.5 text-[#38BDF8]" />
                Open Full Drill-Down
                <ArrowUpRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
