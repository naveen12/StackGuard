import { useMemo, useState } from 'react';
import { ArrowUpDown, Flame, FolderGit2, Layers, RotateCcw, ShieldCheck } from 'lucide-react';
import { Severity, TargetCategory, Vulnerability } from '../types/security';
import { CveCard } from './CveCard';

interface AdvisoriesViewProps {
  vulnerabilities: Vulnerability[];
  initialSeverity: Severity | 'all';
  onSeverityChange: (sev: Severity | 'all') => void;
  onSelectVuln: (vuln: Vulnerability) => void;
  onQuickPatch: (vulnId: string) => void;
}

type SortKey = 'cvss' | 'epss' | 'package';

const CATEGORY_OPTIONS: { id: TargetCategory | 'all'; label: string }[] = [
  { id: 'all', label: 'All Ecosystems' },
  { id: 'container', label: 'Container Images' },
  { id: 'node-lockfile', label: 'Node.js Lockfiles' },
  { id: 'go-module', label: 'Go Modules' },
  { id: 'python-wheel', label: 'Python Wheels' },
];

const SEVERITY_OPTIONS: { id: Severity | 'all'; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
  { id: 'moderate', label: 'Moderate' },
  { id: 'low', label: 'Low' },
  { id: 'safe', label: 'Remediated' },
];

export function AdvisoriesView({
  vulnerabilities,
  initialSeverity,
  onSeverityChange,
  onSelectVuln,
  onQuickPatch,
}: AdvisoriesViewProps) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<TargetCategory | 'all'>('all');
  const [selectedRepo, setSelectedRepo] = useState<string>('all');
  const [groupByRepo, setGroupByRepo] = useState<boolean>(false);
  const [kevOnly, setKevOnly] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>('cvss');

  // Compute distinct repository / file paths across all vulnerabilities
  const repoOptions = useMemo(() => {
    const repos = new Set<string>();
    vulnerabilities.forEach((v) => {
      const repo = v.repositoryPath || v.remediation.filePath || v.targetName;
      if (repo) repos.add(repo);
    });
    return Array.from(repos).sort();
  }, [vulnerabilities]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return vulnerabilities
      .filter((v) => {
        const effSev = v.status === 'patched' ? 'safe' : v.severity;
        const repo = v.repositoryPath || v.remediation.filePath || v.targetName;
        if (initialSeverity !== 'all' && effSev !== initialSeverity) return false;
        if (category !== 'all' && v.targetCategory !== category) return false;
        if (selectedRepo !== 'all' && repo !== selectedRepo) return false;
        if (kevOnly && !v.isKev) return false;
        if (q) {
          const hay = `${v.cveId} ${v.packageName} ${v.installedVersion} ${v.title} ${v.advisory} ${v.targetName} ${repo} ${v.digest}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'epss') return b.epssScore - a.epssScore;
        if (sortBy === 'package') return a.packageName.localeCompare(b.packageName);
        return b.cvssScore - a.cvssScore;
      });
  }, [vulnerabilities, initialSeverity, category, selectedRepo, kevOnly, query, sortBy]);

  // Group filtered advisories by repository path
  const repoGrouped = useMemo(() => {
    const map = new Map<string, Vulnerability[]>();
    filtered.forEach((v) => {
      const repo = v.repositoryPath || v.remediation.filePath || v.targetName;
      const existing = map.get(repo) ?? [];
      existing.push(v);
      map.set(repo, existing);
    });
    return Array.from(map.entries());
  }, [filtered]);

  const resetFilters = () => {
    setQuery('');
    setCategory('all');
    setSelectedRepo('all');
    setKevOnly(false);
    onSeverityChange('all');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-[24px] sm:text-[28px] font-semibold tracking-[-0.02em] text-[#DFE2EF]">
            CVE &amp; Dependency Advisories
          </h1>
          <p className="text-[14px] text-[#94A3B8] mt-0.5">
            Filter active advisories by repository path, CVSS tier, ecosystem lockfile, or CISA KEV exploitation status.
          </p>
        </div>
        <span className="font-mono text-[12px] text-[#8ED5FF] tabular-nums">
          Showing {filtered.length} of {vulnerabilities.length} advisories across {repoOptions.length} repositories
        </span>
      </div>

      {/* Filter & Query Terminal Bar */}
      <div className="obsidian-card rounded-lg p-4 space-y-3.5">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Command Shell Query Input */}
          <div className="terminal-input flex-1 flex items-center gap-2.5 rounded border border-[#1E293B] bg-[#090D16] px-3 py-2 transition-all">
            <span className="font-mono text-[13px] font-semibold text-[#38BDF8] select-none">
              $
            </span>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by CVE ID, package@version, repository path, or advisory..."
              className="w-full bg-transparent font-mono text-[12px] text-[#DFE2EF] placeholder:text-[#64748B] focus:outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Repository Filter Dropdown */}
            <div className="inline-flex items-center gap-1.5 rounded border border-[#1E293B] bg-[#090D16] px-2.5 py-2">
              <FolderGit2 className="h-3.5 w-3.5 text-[#38BDF8]" />
              <select
                value={selectedRepo}
                onChange={(e) => setSelectedRepo(e.target.value)}
                aria-label="Filter by repository path"
                className="bg-transparent font-mono text-[11px] text-[#DFE2EF] focus:outline-none cursor-pointer max-w-[180px] truncate"
              >
                <option value="all" className="bg-[#0F131C]">
                  All Repositories ({repoOptions.length})
                </option>
                {repoOptions.map((r) => (
                  <option key={r} value={r} className="bg-[#0F131C]">
                    {r}
                  </option>
                ))}
              </select>
            </div>

            {/* Ecosystem Dropdown */}
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value as TargetCategory | 'all')}
              aria-label="Filter by ecosystem"
              className="rounded border border-[#1E293B] bg-[#090D16] px-3 py-2 font-mono text-[11px] text-[#DFE2EF] focus:border-[#38BDF8] focus:outline-none cursor-pointer"
            >
              {CATEGORY_OPTIONS.map((opt) => (
                <option key={opt.id} value={opt.id} className="bg-[#0F131C]">
                  {opt.label}
                </option>
              ))}
            </select>

            {/* Sort Dropdown */}
            <div className="inline-flex items-center gap-1.5 rounded border border-[#1E293B] bg-[#090D16] px-2.5 py-2">
              <ArrowUpDown className="h-3.5 w-3.5 text-[#87929A]" />
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as SortKey)}
                aria-label="Sort advisories"
                className="bg-transparent font-mono text-[11px] text-[#DFE2EF] focus:outline-none cursor-pointer"
              >
                <option value="cvss" className="bg-[#0F131C]">
                  Sort: CVSS Score
                </option>
                <option value="epss" className="bg-[#0F131C]">
                  Sort: EPSS Exploit %
                </option>
                <option value="package" className="bg-[#0F131C]">
                  Sort: Package A–Z
                </option>
              </select>
            </div>

            {/* Group Repo-Wise Toggle */}
            <button
              type="button"
              onClick={() => setGroupByRepo((p) => !p)}
              className={`inline-flex items-center gap-1.5 rounded border px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] transition-colors whitespace-nowrap cursor-pointer ${
                groupByRepo
                  ? 'border-[#38BDF8]/60 bg-[#38BDF8]/15 text-[#8ED5FF]'
                  : 'border-[#1E293B] bg-[#090D16] text-[#94A3B8] hover:text-[#DFE2EF]'
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              {groupByRepo ? 'Grouped Repo-Wise' : 'Group Repo-Wise'}
            </button>

            {/* KEV Toggle */}
            <button
              type="button"
              onClick={() => setKevOnly((prev) => !prev)}
              className={`inline-flex items-center gap-1.5 rounded border px-3 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] transition-colors whitespace-nowrap cursor-pointer ${
                kevOnly
                  ? 'border-[#EF4444]/60 bg-[#EF4444]/15 text-[#F87171]'
                  : 'border-[#1E293B] bg-[#090D16] text-[#94A3B8] hover:text-[#DFE2EF]'
              }`}
            >
              <Flame className="h-3.5 w-3.5" />
              KEV Only
            </button>
          </div>
        </div>

        {/* Severity Filter Chips */}
        <div className="flex flex-wrap items-center gap-1.5">
          {SEVERITY_OPTIONS.map((opt) => {
            const active = initialSeverity === opt.id;
            return (
              <button
                key={opt.id}
                type="button"
                onClick={() => onSeverityChange(opt.id)}
                className={`rounded px-2.5 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] border transition-colors whitespace-nowrap cursor-pointer ${
                  active
                    ? 'border-[#38BDF8]/60 bg-[#38BDF8]/15 text-[#8ED5FF]'
                    : 'border-[#1E293B] bg-[#090D16]/60 text-[#94A3B8] hover:text-[#DFE2EF] hover:border-[#334155]'
                }`}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Results List */}
      {filtered.length === 0 ? (
        <div className="obsidian-card rounded-lg p-12 text-center space-y-3">
          <ShieldCheck className="h-8 w-8 text-[#10B981] mx-auto" />
          <h3 className="font-display text-[17px] font-semibold text-[#DFE2EF]">
            No Matching Advisories
          </h3>
          <p className="text-[13px] text-[#94A3B8] max-w-md mx-auto">
            No vulnerabilities match the current query and filter constraints. Clear active filters to inspect all indexed advisories.
          </p>
          <button
            type="button"
            onClick={resetFilters}
            className="inline-flex items-center gap-2 rounded border border-[#38BDF8]/40 bg-[#38BDF8]/12 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#8ED5FF] hover:bg-[#38BDF8] hover:text-[#090D16] transition-colors cursor-pointer"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Reset Filters
          </button>
        </div>
      ) : groupByRepo ? (
        <div className="space-y-6">
          {repoGrouped.map(([repoPath, vulns]) => {
            const critCount = vulns.filter((v) => v.severity === 'critical' && v.status === 'open').length;
            const openCount = vulns.filter((v) => v.status === 'open').length;
            return (
              <div key={repoPath} className="space-y-3">
                <div className="rounded-lg bg-[#090D16] border border-[#1E293B] px-4 py-3 flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <FolderGit2 className="h-4 w-4 text-[#38BDF8] shrink-0" />
                    <span className="font-mono text-[14px] font-semibold text-[#DFE2EF] truncate">
                      {repoPath}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 font-mono text-[11px] tabular-nums">
                    <span className="text-[#8ED5FF] font-semibold">{vulns.length} CVEs</span>
                    <span className="text-[#334155]">·</span>
                    <span className={openCount > 0 ? 'text-[#FB923C]' : 'text-[#34D399]'}>
                      {openCount} Open
                    </span>
                    {critCount > 0 && (
                      <span className="rounded bg-[#EF4444]/15 border border-[#EF4444]/40 px-2 py-0.5 text-[#F87171] font-semibold">
                        {critCount} Critical
                      </span>
                    )}
                  </div>
                </div>
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-3.5 pl-2 border-l-2 border-[#1E293B]">
                  {vulns.map((vuln) => (
                    <CveCard
                      key={vuln.id}
                      vuln={vuln}
                      onSelect={onSelectVuln}
                      onQuickPatch={onQuickPatch}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3.5">
          {filtered.map((vuln) => (
            <CveCard
              key={vuln.id}
              vuln={vuln}
              onSelect={onSelectVuln}
              onQuickPatch={onQuickPatch}
            />
          ))}
        </div>
      )}
    </div>
  );
}
