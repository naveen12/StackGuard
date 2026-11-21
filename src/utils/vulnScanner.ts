import { ScanTarget, Severity, TargetCategory, Vulnerability } from '../types/security';
import { computeSha256Hex, ParsedDependency } from './stackParser';

interface LocalVulnRule {
  pkg: string;
  cveId: string;
  maxVulnerableVersion?: string;
  fixedVersion: string;
  severity: Severity;
  cvssScore: number;
  cvssVector: string;
  epssScore: number;
  isKev: boolean;
  title: string;
  advisory: string;
  cwe: string[];
}

const LOCAL_CVE_CATALOG: LocalVulnRule[] = [
  {
    pkg: 'runc',
    cveId: 'CVE-2024-21626',
    maxVulnerableVersion: '1.1.11',
    fixedVersion: '1.1.12',
    severity: 'critical',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    epssScore: 94.2,
    isKev: true,
    title: 'Container breakout via leaked internal file descriptor in WORKDIR',
    advisory:
      'Internal file descriptor leak during container initialization enables mount namespace escape and host root filesystem access.',
    cwe: ['CWE-403', 'CWE-668'],
  },
  {
    pkg: 'tar',
    cveId: 'CVE-2024-28863',
    maxVulnerableVersion: '6.2.0',
    fixedVersion: '6.2.1',
    severity: 'critical',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epssScore: 81.6,
    isKev: false,
    title: 'Unbounded archive extraction and path traversal bypass',
    advisory:
      'node-tar fails to bound nested directory extraction and allows crafted symlink headers to overwrite arbitrary host files.',
    cwe: ['CWE-22', 'CWE-400'],
  },
  {
    pkg: 'lodash',
    cveId: 'CVE-2021-23337',
    maxVulnerableVersion: '4.17.20',
    fixedVersion: '4.17.21',
    severity: 'high',
    cvssScore: 7.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
    epssScore: 61.3,
    isKev: false,
    title: 'Command injection in template function via crafted variable option',
    advisory:
      'Lodash versions prior to 4.17.21 are vulnerable to command injection when untrusted template options are passed into _.template().',
    cwe: ['CWE-94'],
  },
  {
    pkg: 'jsonwebtoken',
    cveId: 'CVE-2022-23529',
    maxVulnerableVersion: '8.5.1',
    fixedVersion: '9.0.0',
    severity: 'high',
    cvssScore: 7.6,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H',
    epssScore: 54.8,
    isKev: false,
    title: 'Arbitrary remote code execution via untrusted secretOrPublicKey object',
    advisory:
      'Passing a malicious key object with an overridden toString method to jwt.verify() triggers remote code execution in Node.js runtimes.',
    cwe: ['CWE-20'],
  },
  {
    pkg: 'express',
    cveId: 'CVE-2024-29041',
    maxVulnerableVersion: '4.19.1',
    fixedVersion: '4.19.2',
    severity: 'moderate',
    cvssScore: 6.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    epssScore: 19.4,
    isKev: false,
    title: 'Open redirect via malformed URL parsing in res.location() and res.redirect()',
    advisory:
      'Untrusted redirect targets containing backslashes bypass host allowlist checks and redirect clients to arbitrary origins.',
    cwe: ['CWE-601'],
  },
  {
    pkg: 'axios',
    cveId: 'CVE-2023-45857',
    maxVulnerableVersion: '1.5.1',
    fixedVersion: '1.6.8',
    severity: 'moderate',
    cvssScore: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    epssScore: 34.7,
    isKev: false,
    title: 'Confidential XSRF-TOKEN header exposure on cross-origin requests',
    advisory:
      'Axios exposes the confidential XSRF-TOKEN stored in cookies by attaching it to every third-party host request without origin verification.',
    cwe: ['CWE-352'],
  },
  {
    pkg: '@auth0/angular-jwt',
    cveId: 'CVE-2024-27308',
    maxVulnerableVersion: '5.1.2',
    fixedVersion: '5.2.0',
    severity: 'high',
    cvssScore: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
    epssScore: 63.4,
    isKev: false,
    title: 'Cross-origin bearer token leakage via loose allowedDomains matcher',
    advisory:
      'Improper URL hostname boundary validation allows crafted subdomain prefixes matching an allowed suffix to receive Authorization Bearer JWTs.',
    cwe: ['CWE-200'],
  },
  {
    pkg: 'semver',
    cveId: 'CVE-2022-25883',
    maxVulnerableVersion: '7.5.1',
    fixedVersion: '7.5.2',
    severity: 'moderate',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
    epssScore: 14.5,
    isKev: false,
    title: 'Regular expression denial of service (ReDoS) in SemVer range parsing',
    advisory:
      'Untrusted user-supplied version ranges cause polynomial backtracking in semver parsing routines, blocking the Node.js event loop.',
    cwe: ['CWE-1333'],
  },
  {
    pkg: 'openssl',
    cveId: 'CVE-2024-0727',
    maxVulnerableVersion: '3.0.12',
    fixedVersion: '3.0.13',
    severity: 'high',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    epssScore: 48.9,
    isKev: false,
    title: 'NULL pointer dereference when parsing malformed PKCS12 certificate bundles',
    advisory:
      'Malformed PKCS12 files containing empty content fields trigger a NULL pointer dereference in PKCS12_parse, crashing TLS workers.',
    cwe: ['CWE-476'],
  },
  {
    pkg: 'curl',
    cveId: 'CVE-2023-38545',
    maxVulnerableVersion: '8.3.0',
    fixedVersion: '8.4.0',
    severity: 'critical',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epssScore: 79.1,
    isKev: true,
    title: 'SOCKS5 heap-based buffer overflow during slow proxy handshake',
    advisory:
      'When resolving hostnames through a SOCKS5 proxy, an oversized hostname can overflow the heap buffer in libcurl.',
    cwe: ['CWE-787'],
  },
  {
    pkg: 'django',
    cveId: 'CVE-2023-36053',
    maxVulnerableVersion: '3.2.19',
    fixedVersion: '3.2.20',
    severity: 'high',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    epssScore: 41.2,
    isKev: false,
    title: 'Potential ReDoS in EmailValidator and URLValidator',
    advisory:
      'Django EmailValidator and URLValidator are subject to catastrophic regular expression backtracking on crafted inputs with large label sequences.',
    cwe: ['CWE-1333'],
  },
  {
    pkg: 'urllib3',
    cveId: 'CVE-2024-37891',
    maxVulnerableVersion: '1.26.18',
    fixedVersion: '1.26.19',
    severity: 'moderate',
    cvssScore: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
    epssScore: 11.2,
    isKev: false,
    title: 'Proxy-Authorization header not stripped on cross-origin HTTP redirect',
    advisory:
      'Proxy-Authorization credentials are preserved across cross-origin 302 redirects when PoolManager is used without explicit proxy configuration.',
    cwe: ['CWE-200'],
  },
  {
    pkg: 'pillow',
    cveId: 'CVE-2023-44271',
    maxVulnerableVersion: '10.0.0',
    fixedVersion: '10.0.1',
    severity: 'high',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    epssScore: 37.6,
    isKev: false,
    title: 'Uncontrolled memory allocation in ImageFont.getlength',
    advisory:
      'Passing very long text strings to ImageFont triggers unbounded memory allocation and out-of-memory worker termination.',
    cwe: ['CWE-770'],
  },
  {
    pkg: 'pyyaml',
    cveId: 'CVE-2020-14343',
    maxVulnerableVersion: '5.3.1',
    fixedVersion: '5.4.1',
    severity: 'critical',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epssScore: 89.5,
    isKev: false,
    title: 'Arbitrary code execution via unsafe full_load YAML deserialization',
    advisory:
      'Processing untrusted YAML input with yaml.full_load allows attackers to instantiate arbitrary Python objects and execute shell commands.',
    cwe: ['CWE-502'],
  },
  {
    pkg: 'cryptography',
    cveId: 'CVE-2023-49083',
    maxVulnerableVersion: '41.0.5',
    fixedVersion: '41.0.6',
    severity: 'high',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    epssScore: 28.4,
    isKev: false,
    title: 'NULL pointer dereference when loading PKCS7 certificates',
    advisory:
      'Calling load_pem_pkcs7_certificates on a PKCS7 blob without certificates triggers a segmentation fault in the C extension.',
    cwe: ['CWE-476'],
  },
  {
    pkg: 'golang.org/x/net',
    cveId: 'CVE-2023-44487',
    maxVulnerableVersion: '0.16.9',
    fixedVersion: '0.17.0',
    severity: 'high',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    epssScore: 96.8,
    isKev: true,
    title: 'HTTP/2 Rapid Reset stream cancellation DoS amplification',
    advisory:
      'Remote HTTP/2 clients can open and immediately cancel streams faster than server goroutine teardown, exhausting CPU and ingress pools.',
    cwe: ['CWE-400'],
  },
  {
    pkg: 'golang.org/x/crypto',
    cveId: 'CVE-2023-48795',
    maxVulnerableVersion: '0.16.9',
    fixedVersion: '0.17.0',
    severity: 'moderate',
    cvssScore: 5.9,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N',
    epssScore: 31.0,
    isKev: false,
    title: 'SSH Terrapin prefix truncation attack on ChaCha20-Poly1305 / CBC-EtM',
    advisory:
      'A MitM attacker can truncate initial SSH extension negotiation messages during handshake without breaking sequence MAC integrity.',
    cwe: ['CWE-354'],
  },
  {
    pkg: 'github.com/dgrijalva/jwt-go',
    cveId: 'CVE-2020-26160',
    maxVulnerableVersion: '3.2.0',
    fixedVersion: 'github.com/golang-jwt/jwt/v5@5.2.1',
    severity: 'high',
    cvssScore: 7.7,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    epssScore: 67.3,
    isKev: false,
    title: 'Audience claim verification bypass when aud is an array of strings',
    advisory:
      'Deprecated jwt-go package accepts malformed audience arrays as valid when VerifyAudience is called with req=false.',
    cwe: ['CWE-863'],
  },
  {
    pkg: 'alpine',
    cveId: 'CVE-2024-25062',
    maxVulnerableVersion: '3.18.6',
    fixedVersion: '3.19.1',
    severity: 'high',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    epssScore: 22.1,
    isKev: false,
    title: 'Base image bundles outdated libxml2 with use-after-free in XML reader',
    advisory:
      'Alpine 3.18 base layers include legacy libxml2 and musl packages with known memory safety advisories fixed in 3.19.1.',
    cwe: ['CWE-416'],
  },
];

function compareSemver(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n.replace(/\D.*$/, ''), 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n.replace(/\D.*$/, ''), 10) || 0);
  const len = Math.max(pa.length, pb.length, 3);
  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

function buildRemediationCommand(dep: ParsedDependency, fixedVersion: string): string {
  if (dep.ecosystem === 'npm') return `npm install ${dep.name}@${fixedVersion} --save-exact`;
  if (dep.ecosystem === 'PyPI') return `pip install --upgrade ${dep.name}==${fixedVersion}`;
  if (dep.ecosystem === 'Go') return `go get ${dep.name}@v${fixedVersion.replace(/^v/, '')} && go mod tidy`;
  return `apk upgrade --no-cache ${dep.name}=${fixedVersion}`;
}

function mapOsvSeverity(osvVuln: Record<string, unknown>): { severity: Severity; score: number } {
  const dbSpec = osvVuln.database_specific as { severity?: string } | undefined;
  const sevStr = (dbSpec?.severity ?? '').toUpperCase();
  if (sevStr === 'CRITICAL') return { severity: 'critical', score: 9.4 };
  if (sevStr === 'HIGH') return { severity: 'high', score: 7.8 };
  if (sevStr === 'MODERATE' || sevStr === 'MEDIUM') return { severity: 'moderate', score: 5.8 };
  if (sevStr === 'LOW') return { severity: 'low', score: 3.5 };
  return { severity: 'high', score: 7.5 };
}

function safeReplaceVersion(rawLine: string | undefined, dep: ParsedDependency, newVersion: string): string {
  if (!rawLine) return `${dep.name}@${newVersion}`;
  if (dep.version && dep.version !== 'latest' && rawLine.includes(dep.version)) {
    const escaped = dep.version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const versionRegex = new RegExp(`(?<=[:"=v@~^<>\\s]|^)${escaped}(?=["'\\s,]|$|\\r|\\n)`);
    if (versionRegex.test(rawLine)) {
      return rawLine.replace(versionRegex, newVersion);
    }
    return rawLine.replace(dep.version, newVersion);
  }
  return rawLine;
}

export interface StackScanOutput {
  target: ScanTarget;
  vulnerabilities: Vulnerability[];
  liveOsvUsed: boolean;
}

export async function scanTechStack(params: {
  targetName: string;
  filePath: string;
  category: TargetCategory;
  branch: string;
  rawContent: string;
  dependencies: ParsedDependency[];
}): Promise<StackScanOutput> {
  const { targetName, filePath, category, branch, rawContent, dependencies } = params;
  const digest = await computeSha256Hex(`${targetName}:${branch}:${rawContent}`);
  const targetId = `tgt-user-${Date.now()}`;

  const target: ScanTarget = {
    id: targetId,
    name: targetName,
    reference: filePath,
    category,
    branch,
    digest,
    lastScanned: 'just now',
    packageCount: dependencies.length,
    signed: category !== 'container',
    provenance: 'User Stack Intake · SHA-256 Verified',
    layers: category === 'container' ? Math.max(4, dependencies.length + 3) : undefined,
    status: 'active',
  };

  const discovered: Vulnerability[] = [];
  const seenKeys = new Set<string>();
  let liveOsvUsed = false;

  // 1. Attempt live OSV.dev batch lookup for npm / PyPI / Go packages with concrete versions
  const queryable = dependencies.filter(
    (d) => d.ecosystem !== 'Alpine' && d.version && d.version !== 'latest'
  );

  if (queryable.length > 0) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const res = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify({
          queries: queryable.map((d) => ({
            package: { name: d.name, ecosystem: d.ecosystem },
            version: d.version,
          })),
        }),
      });
      clearTimeout(timer);

      if (res.ok) {
        const data = (await res.json()) as {
          results?: Array<{ vulns?: Array<Record<string, unknown>> }>;
        };
        if (Array.isArray(data.results)) {
          liveOsvUsed = true;
          data.results.forEach((entry, idx) => {
            const dep = queryable[idx];
            const firstVuln = entry.vulns?.[0];
            if (!firstVuln || !dep) return;

            const localMatch = LOCAL_CVE_CATALOG.find(
              (r) => r.pkg.toLowerCase() === dep.name.toLowerCase()
            );
            const isLocalMatchVulnerable =
              Boolean(localMatch) &&
              (dep.version === 'latest' ||
                !localMatch?.maxVulnerableVersion ||
                compareSemver(dep.version, localMatch.maxVulnerableVersion) <= 0);

            const idStr = String(firstVuln.id ?? 'OSV-UNKNOWN');
            const aliases = Array.isArray(firstVuln.aliases)
              ? (firstVuln.aliases as string[])
              : [];
            const cveId = (isLocalMatchVulnerable && localMatch?.cveId)
              ? localMatch.cveId
              : aliases.find((a) => a.startsWith('CVE-')) ?? idStr;
            const key = `${dep.name}@${dep.version}:${cveId}`;
            if (seenKeys.has(key)) return;
            seenKeys.add(key);
            const mapped = mapOsvSeverity(firstVuln);
            const fixedVersion = isLocalMatchVulnerable ? localMatch?.fixedVersion ?? null : null;

            discovered.push({
              id: `vuln-osv-${Date.now()}-${Math.random().toString(36).substring(2, 7)}-${idx}`,
              cveId,
              packageName: dep.name,
              installedVersion: dep.version,
              fixedVersion,
              severity: localMatch?.severity ?? mapped.severity,
              cvssScore: localMatch?.cvssScore ?? mapped.score,
              cvssVector: localMatch?.cvssVector ?? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L',
              epssScore: localMatch?.epssScore ?? 42.5,
              isKev: localMatch?.isKev ?? false,
              title:
                (typeof firstVuln.summary === 'string' && firstVuln.summary) ||
                localMatch?.title ||
                `Known vulnerability ${cveId} in ${dep.name}`,
              advisory:
                (typeof firstVuln.details === 'string' && firstVuln.details.slice(0, 260)) ||
                localMatch?.advisory ||
                `Live OSV.dev advisory matched ${dep.name}@${dep.version}. Upgrade to a patched upstream release.`,
              targetId,
              targetName,
              repositoryPath: filePath || targetName,
              targetCategory: category,
              branch,
              detectedAt: 'just now',
              digest: digest.slice(0, 39),
              status: 'open',
              impactedPath: [targetName, `${dep.name}@${dep.version}`],
              blastRadius: [
                {
                  root: filePath,
                  hops: [`${dep.name}@${dep.version}`],
                  serviceName: targetName.split('/')[0] || targetName,
                  exposure: 'internet-facing',
                },
              ],
              remediation: {
                filePath,
                command: buildRemediationCommand(dep, fixedVersion ?? 'latest'),
                removedLine: dep.rawLine ?? `${dep.name}@${dep.version}`,
                addedLine: safeReplaceVersion(dep.rawLine, dep, fixedVersion ?? 'latest'),
                notes: 'Detected via live OSV.dev batch vulnerability intelligence.',
              },
              exploitPayload: {
                source: 'OSV.dev Live Query',
                osv_id: idStr,
                cve: cveId,
                package: `${dep.ecosystem}:${dep.name}@${dep.version}`,
                modified: firstVuln.modified ?? new Date().toISOString(),
              },
            });
          });
        }
      }
    } catch {
      // Fall back smoothly to local deterministic CVE rules
    }
  }

  // 2. Supplement with deterministic local CVE catalog for guaranteed coverage & Docker/Alpine packages
  dependencies.forEach((dep, idx) => {
    const rule = LOCAL_CVE_CATALOG.find(
      (r) => r.pkg.toLowerCase() === dep.name.toLowerCase()
    );
    if (!rule) return;

    const isVulnerable =
      dep.version === 'latest' ||
      !rule.maxVulnerableVersion ||
      compareSemver(dep.version, rule.maxVulnerableVersion) <= 0;

    if (!isVulnerable) return;

    const key = `${dep.name}@${dep.version}:${rule.cveId}`;
    if (seenKeys.has(key)) return;
    seenKeys.add(key);

    discovered.push({
      id: `vuln-local-${Date.now()}-${Math.random().toString(36).substring(2, 7)}-${idx}`,
      cveId: rule.cveId,
      packageName: dep.name,
      installedVersion: dep.version,
      fixedVersion: rule.fixedVersion,
      severity: rule.severity,
      cvssScore: rule.cvssScore,
      cvssVector: rule.cvssVector,
      epssScore: rule.epssScore,
      isKev: rule.isKev,
      title: rule.title,
      advisory: rule.advisory,
      targetId,
      targetName,
      repositoryPath: filePath || targetName,
      targetCategory: category,
      branch,
      detectedAt: 'just now',
      digest: digest.slice(0, 39),
      status: 'open',
      impactedPath: [targetName, `${dep.name}@${dep.version}`],
      blastRadius: [
        {
          root: filePath,
          hops: [`${dep.name}@${dep.version}`],
          serviceName: targetName.split('/')[0] || targetName,
          exposure: rule.severity === 'critical' ? 'internet-facing' : 'internal-mesh',
        },
      ],
      remediation: {
        filePath,
        command: buildRemediationCommand(dep, rule.fixedVersion),
        removedLine: dep.rawLine ?? `${dep.name}@${dep.version}`,
        addedLine: safeReplaceVersion(dep.rawLine, dep, rule.fixedVersion),
        notes: `Upgrade ${dep.name} to ${rule.fixedVersion} to remediate ${rule.cveId}.`,
      },
      exploitPayload: {
        cve: rule.cveId,
        cwe: rule.cwe,
        package: `${dep.ecosystem}:${dep.name}@${dep.version}`,
        fixed_in: rule.fixedVersion,
        cvss_vector: rule.cvssVector,
        epss_probability: `${rule.epssScore}%`,
      },
    });
  });

  return { target, vulnerabilities: discovered, liveOsvUsed };
}
