import { ChangeEvent, useMemo, useRef, useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  FileCode2,
  Loader2,
  Plus,
  Radar,
  ShieldAlert,
  Trash2,
  Upload,
} from 'lucide-react';
import { ScanTarget, ScreenId, TargetCategory, Vulnerability } from '../types/security';
import {
  detectManifestKind,
  ManifestKind,
  ParsedDependency,
  parseTechStack,
  SAMPLE_MANIFESTS,
} from '../utils/stackParser';
import { scanTechStack } from '../utils/vulnScanner';

interface StackIntakeViewProps {
  selectedBranch: string;
  onStackScanned: (result: {
    target: ScanTarget;
    vulnerabilities: Vulnerability[];
    replaceWorkspace: boolean;
    liveOsvUsed: boolean;
  }) => void;
  onNavigate: (screen: ScreenId) => void;
}

type IntakeTab = 'manifest' | 'builder';

const ECOSYSTEM_OPTIONS: {
  id: ParsedDependency['ecosystem'];
  label: string;
  category: TargetCategory;
  placeholder: string;
}[] = [
  { id: 'npm', label: 'Node.js / npm', category: 'node-lockfile', placeholder: 'e.g. express' },
  { id: 'PyPI', label: 'Python / PyPI', category: 'python-wheel', placeholder: 'e.g. django' },
  { id: 'Go', label: 'Go Module', category: 'go-module', placeholder: 'e.g. golang.org/x/net' },
  { id: 'Alpine', label: 'Docker / Alpine', category: 'container', placeholder: 'e.g. openssl' },
];

export function StackIntakeView({
  selectedBranch,
  onStackScanned,
  onNavigate,
}: StackIntakeViewProps) {
  const [tab, setTab] = useState<IntakeTab>('manifest');
  const [manifestContent, setManifestContent] = useState<string>(
    SAMPLE_MANIFESTS['package.json'].content
  );
  const [manifestKind, setManifestKind] = useState<ManifestKind>('package.json');
  const [targetName, setTargetName] = useState<string>(
    SAMPLE_MANIFESTS['package.json'].targetName
  );
  const [filePath, setFilePath] = useState<string>(SAMPLE_MANIFESTS['package.json'].filePath);
  const [replaceWorkspace, setReplaceWorkspace] = useState<boolean>(false);

  // Manual Builder State
  const [builderEcosystem, setBuilderEcosystem] = useState<ParsedDependency['ecosystem']>('npm');
  const [pkgInput, setPkgInput] = useState('');
  const [verInput, setVerInput] = useState('');
  const [manualDeps, setManualDeps] = useState<ParsedDependency[]>([
    { name: 'express', version: '4.18.2', ecosystem: 'npm' },
    { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
    { name: 'jsonwebtoken', version: '8.5.1', ecosystem: 'npm' },
  ]);

  const [isScanning, setIsScanning] = useState(false);
  const [lastResult, setLastResult] = useState<{
    targetName: string;
    depCount: number;
    vulnCount: number;
    critCount: number;
    liveOsvUsed: boolean;
  } | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const parsedManifest = useMemo(
    () => parseTechStack(manifestContent, manifestKind, filePath),
    [manifestContent, manifestKind, filePath]
  );

  const activeDependencies = tab === 'manifest' ? parsedManifest.dependencies : manualDeps;

  const handleLoadSample = (kind: Exclude<ManifestKind, 'manual'>) => {
    const sample = SAMPLE_MANIFESTS[kind];
    setManifestKind(kind);
    setManifestContent(sample.content);
    setTargetName(sample.targetName);
    setFilePath(sample.filePath);
    setLastResult(null);
  };

  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      const detected = detectManifestKind(text, file.name);
      setManifestKind(detected);
      setManifestContent(text);
      setTargetName(file.name);
      setFilePath(file.name);
      setLastResult(null);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleAddManualDep = () => {
    const cleanPkg = pkgInput.trim();
    const cleanVer = verInput.trim() || 'latest';
    if (!cleanPkg) return;
    setManualDeps((prev) => [
      ...prev,
      { name: cleanPkg, version: cleanVer, ecosystem: builderEcosystem },
    ]);
    setPkgInput('');
    setVerInput('');
  };

  const handleRemoveManualDep = (idx: number) => {
    setManualDeps((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleScan = async () => {
    if (activeDependencies.length === 0 || isScanning) return;
    setIsScanning(true);

    const activeCategory: TargetCategory =
      tab === 'manifest'
        ? parsedManifest.category
        : ECOSYSTEM_OPTIONS.find((e) => e.id === builderEcosystem)?.category ?? 'node-lockfile';

    const resolvedName =
      targetName.trim() ||
      (tab === 'manifest' ? parsedManifest.suggestedTargetName : `custom-${builderEcosystem}-stack`);
    const resolvedPath =
      filePath.trim() || (tab === 'manifest' ? parsedManifest.suggestedFilePath : 'custom-stack');

    const rawBody =
      tab === 'manifest'
        ? manifestContent
        : manualDeps.map((d) => `${d.name}@${d.version}`).join('\n');

    const result = await scanTechStack({
      targetName: resolvedName,
      filePath: resolvedPath,
      category: activeCategory,
      branch: selectedBranch,
      rawContent: rawBody,
      dependencies: activeDependencies,
    });

    setIsScanning(false);
    setLastResult({
      targetName: result.target.name,
      depCount: activeDependencies.length,
      vulnCount: result.vulnerabilities.length,
      critCount: result.vulnerabilities.filter((v) => v.severity === 'critical').length,
      liveOsvUsed: result.liveOsvUsed,
    });

    onStackScanned({
      target: result.target,
      vulnerabilities: result.vulnerabilities,
      replaceWorkspace,
      liveOsvUsed: result.liveOsvUsed,
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-[24px] sm:text-[28px] font-semibold tracking-[-0.02em] text-[#DFE2EF]">
            Feed Your Tech Stack
          </h1>
          <p className="text-[14px] text-[#94A3B8] mt-0.5">
            Upload or paste your <span className="font-mono text-[#8ED5FF]">package.json</span>,{' '}
            <span className="font-mono text-[#8ED5FF]">requirements.txt</span>,{' '}
            <span className="font-mono text-[#8ED5FF]">go.mod</span>, or{' '}
            <span className="font-mono text-[#8ED5FF]">Dockerfile</span> — or build a dependency
            list manually to run live CVE analysis.
          </p>
        </div>

        {/* Mode Switcher */}
        <div className="inline-flex rounded border border-[#1E293B] bg-[#090D16] p-1 gap-1">
          <button
            type="button"
            onClick={() => setTab('manifest')}
            className={`rounded px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] transition-colors cursor-pointer whitespace-nowrap ${
              tab === 'manifest'
                ? 'bg-[#38BDF8]/15 text-[#8ED5FF] border border-[#38BDF8]/40'
                : 'text-[#94A3B8] hover:text-[#DFE2EF] border border-transparent'
            }`}
          >
            Paste / Upload Manifest
          </button>
          <button
            type="button"
            onClick={() => setTab('builder')}
            className={`rounded px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] transition-colors cursor-pointer whitespace-nowrap ${
              tab === 'builder'
                ? 'bg-[#38BDF8]/15 text-[#8ED5FF] border border-[#38BDF8]/40'
                : 'text-[#94A3B8] hover:text-[#DFE2EF] border border-transparent'
            }`}
          >
            Manual Stack Builder
          </button>
        </div>
      </div>

      {/* Main Two-Column Intake Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left: Manifest Editor / Builder */}
        <div className="lg:col-span-7 obsidian-card rounded-lg p-5 space-y-4">
          {/* Artifact Metadata Fields */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="space-y-1.5 block">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                Service / Artifact Name
              </span>
              <input
                type="text"
                value={targetName}
                onChange={(e) => setTargetName(e.target.value)}
                placeholder="e.g. payments-api/package.json"
                className="w-full rounded border border-[#1E293B] bg-[#090D16] px-3 py-2 font-mono text-[12px] text-[#DFE2EF] focus:border-[#38BDF8] focus:outline-none"
              />
            </label>

            <label className="space-y-1.5 block">
              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-[#87929A]">
                Repository Path
              </span>
              <input
                type="text"
                value={filePath}
                onChange={(e) => setFilePath(e.target.value)}
                placeholder="e.g. services/payments-api/package.json"
                className="w-full rounded border border-[#1E293B] bg-[#090D16] px-3 py-2 font-mono text-[12px] text-[#DFE2EF] focus:border-[#38BDF8] focus:outline-none"
              />
            </label>
          </div>

          {tab === 'manifest' ? (
            <>
              {/* Preset Templates & File Upload Row */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  {(Object.keys(SAMPLE_MANIFESTS) as Array<Exclude<ManifestKind, 'manual'>>).map(
                    (kind) => (
                      <button
                        key={kind}
                        type="button"
                        onClick={() => handleLoadSample(kind)}
                        className={`rounded border px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.06em] transition-colors cursor-pointer whitespace-nowrap ${
                          manifestKind === kind
                            ? 'border-[#38BDF8]/50 bg-[#38BDF8]/12 text-[#8ED5FF]'
                            : 'border-[#1E293B] bg-[#090D16] text-[#94A3B8] hover:text-[#DFE2EF]'
                        }`}
                      >
                        {kind}
                      </button>
                    )
                  )}
                </div>

                <div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".json,.txt,.mod,.sum,.yaml,.yml,Dockerfile"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="inline-flex items-center gap-1.5 rounded border border-[#334155] bg-[#111827] px-3 py-1.5 font-mono text-[11px] font-medium text-[#DFE2EF] hover:border-[#38BDF8]/60 hover:text-[#8ED5FF] transition-colors cursor-pointer whitespace-nowrap"
                  >
                    <Upload className="h-3.5 w-3.5 text-[#38BDF8]" />
                    Upload File
                  </button>
                </div>
              </div>

              {/* Raw Manifest Terminal Textarea */}
              <div className="terminal-input rounded border border-[#1E293B] bg-[#090D16] overflow-hidden transition-all">
                <div className="px-3.5 py-2 border-b border-[#1E293B] flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.08em] text-[#87929A]">
                  <span className="flex items-center gap-1.5">
                    <FileCode2 className="h-3.5 w-3.5 text-[#6366F1]" />
                    Detected Format: <strong className="text-[#8ED5FF]">{manifestKind}</strong>
                  </span>
                  <span className="tabular-nums">{manifestContent.split('\n').length} lines</span>
                </div>
                <textarea
                  value={manifestContent}
                  onChange={(e) => {
                    const next = e.target.value;
                    setManifestContent(next);
                    setManifestKind(detectManifestKind(next, filePath));
                  }}
                  rows={12}
                  spellCheck={false}
                  placeholder="Paste package.json, requirements.txt, go.mod, Dockerfile, or one package@version per line..."
                  className="w-full bg-transparent p-3.5 font-mono text-[12px] leading-6 text-[#DFE2EF] placeholder:text-[#64748B] focus:outline-none resize-y"
                />
              </div>
            </>
          ) : (
            <div className="space-y-4">
              {/* Ecosystem selector */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {ECOSYSTEM_OPTIONS.map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setBuilderEcosystem(opt.id)}
                    className={`rounded border px-2.5 py-2 font-mono text-[11px] font-semibold transition-colors cursor-pointer ${
                      builderEcosystem === opt.id
                        ? 'border-[#38BDF8]/60 bg-[#38BDF8]/15 text-[#8ED5FF]'
                        : 'border-[#1E293B] bg-[#090D16] text-[#94A3B8] hover:text-[#DFE2EF]'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              {/* Add Dependency Row */}
              <div className="flex flex-col sm:flex-row gap-2">
                <input
                  type="text"
                  value={pkgInput}
                  onChange={(e) => setPkgInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddManualDep()}
                  placeholder={
                    ECOSYSTEM_OPTIONS.find((e) => e.id === builderEcosystem)?.placeholder ??
                    'Package name'
                  }
                  className="flex-1 rounded border border-[#1E293B] bg-[#090D16] px-3 py-2 font-mono text-[12px] text-[#DFE2EF] focus:border-[#38BDF8] focus:outline-none"
                />
                <input
                  type="text"
                  value={verInput}
                  onChange={(e) => setVerInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddManualDep()}
                  placeholder="Version (e.g. 4.18.2)"
                  className="sm:w-44 rounded border border-[#1E293B] bg-[#090D16] px-3 py-2 font-mono text-[12px] text-[#DFE2EF] focus:border-[#38BDF8] focus:outline-none"
                />
                <button
                  type="button"
                  onClick={handleAddManualDep}
                  className="inline-flex items-center justify-center gap-1.5 rounded border border-[#38BDF8]/50 bg-[#38BDF8]/12 px-4 py-2 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#8ED5FF] hover:bg-[#38BDF8] hover:text-[#090D16] transition-colors cursor-pointer whitespace-nowrap"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Add
                </button>
              </div>

              {/* Added Package List */}
              <div className="rounded border border-[#1E293B] bg-[#090D16] divide-y divide-[#1E293B] max-h-[260px] overflow-y-auto">
                {manualDeps.length === 0 ? (
                  <div className="p-6 text-center font-mono text-[12px] text-[#87929A]">
                    Add packages above to assemble your tech stack.
                  </div>
                ) : (
                  manualDeps.map((dep, idx) => (
                    <div
                      key={`${dep.name}-${idx}`}
                      className="px-3.5 py-2.5 flex items-center justify-between gap-3 font-mono text-[12px]"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className="rounded border border-[#334155] bg-[#111827] px-1.5 py-0.5 text-[10px] text-[#C0C1FF] uppercase">
                          {dep.ecosystem}
                        </span>
                        <span className="text-[#DFE2EF] truncate">
                          {dep.name}
                          <span className="text-[#87929A]">@{dep.version}</span>
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveManualDep(idx)}
                        aria-label={`Remove ${dep.name}`}
                        className="text-[#87929A] hover:text-[#EF4444] p-1 transition-colors cursor-pointer"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right: Parsed Preview + Scan Controls */}
        <div className="lg:col-span-5 space-y-4">
          <div className="obsidian-card rounded-lg p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="font-display text-[17px] font-semibold text-[#DFE2EF]">
                Parsed Stack Preview
              </h2>
              <span className="font-mono text-[11px] font-semibold text-[#8ED5FF] tabular-nums">
                {activeDependencies.length} packages ready
              </span>
            </div>

            {activeDependencies.length === 0 ? (
              <div className="rounded border border-[#1E293B] bg-[#090D16]/70 p-5 text-center font-mono text-[12px] text-[#87929A]">
                No dependencies detected yet. Paste a manifest or choose a sample template.
              </div>
            ) : (
              <div className="rounded border border-[#1E293B] bg-[#090D16]/75 p-3 max-h-[220px] overflow-y-auto space-y-1.5">
                {activeDependencies.map((dep, i) => (
                  <div
                    key={`${dep.name}-${dep.version}-${i}`}
                    className="flex items-center justify-between gap-2 font-mono text-[11px] px-2 py-1 rounded bg-[#111827]/75"
                  >
                    <span className="text-[#DFE2EF] truncate">
                      {dep.name}
                      <span className="text-[#87929A]">@{dep.version}</span>
                    </span>
                    <span className="text-[10px] uppercase tracking-[0.06em] text-[#6366F1] shrink-0">
                      {dep.ecosystem}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {/* Workspace Merge / Replace Option */}
            <label className="flex items-start gap-2.5 rounded border border-[#1E293B] bg-[#090D16]/60 p-3 cursor-pointer">
              <input
                type="checkbox"
                checked={replaceWorkspace}
                onChange={(e) => setReplaceWorkspace(e.target.checked)}
                className="mt-0.5 accent-[#38BDF8]"
              />
              <span className="text-[12px] leading-relaxed text-[#BDC8D1]">
                <strong className="text-[#DFE2EF] block font-medium">
                  Replace default sample workspace
                </strong>
                Clear preloaded demo targets so Telemetry, Advisories, and Blast Graph reflect only your scanned stack.
              </span>
            </label>

            {/* Primary Scan Trigger */}
            <button
              type="button"
              disabled={activeDependencies.length === 0 || isScanning}
              onClick={handleScan}
              className={`w-full inline-flex items-center justify-center gap-2 rounded bg-[#38BDF8] px-4 py-2.5 font-display text-[14px] font-semibold text-[#090D16] hover:bg-[#7BD0FF] active:scale-[0.98] transition-all cursor-pointer disabled:opacity-45 ${
                isScanning ? 'glow-scanner' : ''
              }`}
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Querying OSV.dev &amp; CVE Signatures…
                </>
              ) : (
                <>
                  <Radar className="h-4 w-4" />
                  Analyze &amp; Scan Tech Stack
                </>
              )}
            </button>

            <p className="font-mono text-[10px] text-[#87929A] leading-relaxed">
              Queries live Open Source Vulnerabilities (OSV.dev) intelligence paired with local CVE/EPSS rules and computes a client-side SHA-256 artifact digest.
            </p>
          </div>

          {/* Scan Result Confirmation Card */}
          {lastResult && (
            <div
              className={`obsidian-card rounded-lg p-5 space-y-3 ${
                lastResult.critCount > 0 ? 'glow-critical border-[#EF4444]/40' : 'border-[#10B981]/40'
              }`}
            >
              <div className="flex items-start gap-3">
                {lastResult.vulnCount > 0 ? (
                  <ShieldAlert className="h-5 w-5 text-[#F87171] shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle2 className="h-5 w-5 text-[#34D399] shrink-0 mt-0.5" />
                )}
                <div className="space-y-1">
                  <h3 className="font-display text-[15px] font-semibold text-[#DFE2EF]">
                    Scan Complete · {lastResult.targetName}
                  </h3>
                  <p className="text-[13px] text-[#94A3B8]">
                    Indexed{' '}
                    <strong className="font-mono text-[#DFE2EF] tabular-nums">
                      {lastResult.depCount}
                    </strong>{' '}
                    dependencies and identified{' '}
                    <strong
                      className={`font-mono tabular-nums ${
                        lastResult.vulnCount > 0 ? 'text-[#F87171]' : 'text-[#34D399]'
                      }`}
                    >
                      {lastResult.vulnCount}
                    </strong>{' '}
                    vulnerabilities
                    {lastResult.liveOsvUsed ? ' (OSV.dev live + local rules).' : ' (local CVE catalog).'}
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => onNavigate('advisories')}
                  className="inline-flex items-center gap-1.5 rounded border border-[#38BDF8]/40 bg-[#38BDF8]/12 px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#8ED5FF] hover:bg-[#38BDF8] hover:text-[#090D16] transition-colors cursor-pointer"
                >
                  Inspect Advisories
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('graph')}
                  className="inline-flex items-center gap-1.5 rounded border border-[#1E293B] bg-[#090D16] px-3 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.06em] text-[#BDC8D1] hover:border-[#6366F1]/60 hover:text-[#DFE2EF] transition-colors cursor-pointer"
                >
                  View Blast Graph
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
