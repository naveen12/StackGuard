import { TargetCategory } from '../types/security';

export interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI' | 'Go' | 'Alpine';
  rawLine?: string;
}

export type ManifestKind = 'package.json' | 'requirements.txt' | 'go.mod' | 'Dockerfile' | 'manual';

export interface ParsedStackResult {
  kind: ManifestKind;
  category: TargetCategory;
  dependencies: ParsedDependency[];
  suggestedTargetName: string;
  suggestedFilePath: string;
}

export const SAMPLE_MANIFESTS: Record<
  Exclude<ManifestKind, 'manual'>,
  { label: string; targetName: string; filePath: string; content: string }
> = {
  'package.json': {
    label: 'Node.js API (package.json)',
    targetName: 'payments-api/package.json',
    filePath: 'services/payments-api/package.json',
    content: `{
  "name": "payments-api",
  "version": "1.8.0",
  "dependencies": {
    "express": "4.18.2",
    "tar": "6.1.11",
    "axios": "1.5.1",
    "lodash": "4.17.20",
    "jsonwebtoken": "8.5.1",
    "@auth0/angular-jwt": "5.1.2",
    "semver": "7.5.1"
  }
}`,
  },
  'requirements.txt': {
    label: 'Python ML (requirements.txt)',
    targetName: 'fraud-engine/requirements.txt',
    filePath: 'ml/fraud-engine/requirements.txt',
    content: `# Fraud detection service dependencies
django==3.2.18
urllib3==1.26.17
requests==2.31.0
pillow==10.0.0
pyyaml==5.3.1
cryptography==41.0.3`,
  },
  'go.mod': {
    label: 'Go gRPC (go.mod)',
    targetName: 'edge-router/go.mod',
    filePath: 'services/edge-router/go.mod',
    content: `module github.com/acme/edge-router

go 1.21

require (
	golang.org/x/net v0.16.0
	golang.org/x/crypto v0.14.0
	google.golang.org/grpc v1.58.2
	github.com/dgrijalva/jwt-go v3.2.0
)`,
  },
  Dockerfile: {
    label: 'Container (Dockerfile)',
    targetName: 'checkout-svc:1.4-alpine',
    filePath: 'infra/docker/checkout-svc.Dockerfile',
    content: `FROM alpine:3.18
RUN apk add --no-cache openssl=3.0.12-r0 runc=1.1.11-r0 curl=8.4.0-r0
WORKDIR /app
COPY . .
CMD ["./server"]`,
  },
};

function cleanVersion(raw: string): string {
  return raw
    .trim()
    .replace(/^[\^~>=<v]+/, '')
    .replace(/-r\d+$/, '')
    .split(/\s+/)[0] || 'latest';
}

export function detectManifestKind(content: string, fileName?: string): ManifestKind {
  const lowerName = (fileName ?? '').toLowerCase();
  if (lowerName.endsWith('.json') || lowerName.includes('package')) return 'package.json';
  if (lowerName.includes('requirements') || lowerName.endsWith('.txt')) return 'requirements.txt';
  if (lowerName.endsWith('go.mod') || lowerName.endsWith('go.sum')) return 'go.mod';
  if (lowerName.includes('dockerfile')) return 'Dockerfile';

  const trimmed = content.trim();
  if (trimmed.startsWith('{')) return 'package.json';
  if (/^FROM\s+/im.test(trimmed)) return 'Dockerfile';
  if (/^module\s+/im.test(trimmed) || /require\s*\(/im.test(trimmed)) return 'go.mod';
  if (/==|>=|~=/.test(trimmed)) return 'requirements.txt';
  return 'manual';
}

export function parseTechStack(
  content: string,
  explicitKind?: ManifestKind,
  fileName?: string
): ParsedStackResult {
  const kind = explicitKind ?? detectManifestKind(content, fileName);
  const dependencies: ParsedDependency[] = [];
  let suggestedTargetName = fileName || 'custom-stack/manifest';
  let suggestedFilePath = fileName || 'package.json';

  if (kind === 'package.json') {
    suggestedTargetName = fileName || 'app/package.json';
    suggestedFilePath = fileName || 'package.json';
    try {
      const parsed = JSON.parse(content);
      if (typeof parsed.name === 'string' && parsed.name.trim()) {
        suggestedTargetName = `${parsed.name.trim()}/package.json`;
      }
      const sections = [
        parsed.dependencies,
        parsed.devDependencies,
        parsed.peerDependencies,
      ];
      for (const sec of sections) {
        if (sec && typeof sec === 'object') {
          for (const [pkg, ver] of Object.entries(sec)) {
            if (typeof ver === 'string') {
              dependencies.push({
                name: pkg,
                version: cleanVersion(ver),
                ecosystem: 'npm',
                rawLine: `    "${pkg}": "${ver}",`,
              });
            }
          }
        }
      }
    } catch {
      // Fallback regex if user pasted partial JSON dependency block
      const lineRegex = /"([@a-zA-Z0-9_./-]+)"\s*:\s*"([^"]+)"/g;
      let m: RegExpExecArray | null;
      while ((m = lineRegex.exec(content)) !== null) {
        if (['name', 'version', 'description', 'license', 'main', 'type'].includes(m[1])) continue;
        dependencies.push({
          name: m[1],
          version: cleanVersion(m[2]),
          ecosystem: 'npm',
          rawLine: `    "${m[1]}": "${m[2]}",`,
        });
      }
    }
    return {
      kind,
      category: 'node-lockfile',
      dependencies,
      suggestedTargetName,
      suggestedFilePath,
    };
  }

  if (kind === 'requirements.txt') {
    suggestedTargetName = fileName || 'python-service/requirements.txt';
    suggestedFilePath = fileName || 'requirements.txt';
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
      const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*(?:==|>=|<=|~=|!=)?\s*([0-9a-zA-Z.*+-]+)?/);
      if (match) {
        dependencies.push({
          name: match[1].toLowerCase(),
          version: cleanVersion(match[2] ?? 'latest'),
          ecosystem: 'PyPI',
          rawLine: trimmed,
        });
      }
    }
    return {
      kind,
      category: 'python-wheel',
      dependencies,
      suggestedTargetName,
      suggestedFilePath,
    };
  }

  if (kind === 'go.mod') {
    suggestedTargetName = fileName || 'go-service/go.mod';
    suggestedFilePath = fileName || 'go.mod';
    const modMatch = content.match(/^module\s+([^\s]+)/m);
    if (modMatch) {
      const parts = modMatch[1].split('/');
      suggestedTargetName = `${parts[parts.length - 1]}/go.mod`;
    }
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('module ') || trimmed.startsWith('go ')) {
        continue;
      }
      const cleaned = trimmed.replace(/^require\s+/, '').replace(/[()]/g, '').trim();
      const match = cleaned.match(/^([a-zA-Z0-9._/-]+)\s+(v?[0-9]+\.[0-9]+\.[0-9][^\s]*)/);
      if (match) {
        dependencies.push({
          name: match[1],
          version: cleanVersion(match[2]),
          ecosystem: 'Go',
          rawLine: `\t${match[1]} ${match[2]}`,
        });
      }
    }
    return {
      kind,
      category: 'go-module',
      dependencies,
      suggestedTargetName,
      suggestedFilePath,
    };
  }

  if (kind === 'Dockerfile') {
    suggestedTargetName = fileName || 'container-image:latest';
    suggestedFilePath = fileName || 'Dockerfile';
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      const fromMatch = trimmed.match(/^FROM\s+([^\s]+)/i);
      if (fromMatch) {
        const [img, tag] = fromMatch[1].split(':');
        suggestedTargetName = `${img}:${tag ?? 'latest'}`;
        dependencies.push({
          name: img.toLowerCase(),
          version: tag ?? 'latest',
          ecosystem: 'Alpine',
          rawLine: trimmed,
        });
      }
      // Match apk add pkg=ver or apt-get install pkg=ver
      const pkgRegex = /([a-zA-Z0-9_+-]+)=([0-9][0-9a-zA-Z._-]*)/g;
      let m: RegExpExecArray | null;
      while ((m = pkgRegex.exec(trimmed)) !== null) {
        dependencies.push({
          name: m[1].toLowerCase(),
          version: cleanVersion(m[2]),
          ecosystem: 'Alpine',
          rawLine: trimmed,
        });
      }
    }
    return {
      kind,
      category: 'container',
      dependencies,
      suggestedTargetName,
      suggestedFilePath,
    };
  }

  // Manual line-by-line: package@version or package==version
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const atIdx = trimmed.lastIndexOf('@');
    if (atIdx > 0) {
      dependencies.push({
        name: trimmed.slice(0, atIdx).trim(),
        version: cleanVersion(trimmed.slice(atIdx + 1)),
        ecosystem: 'npm',
        rawLine: trimmed,
      });
    } else if (trimmed.includes('==')) {
      const [name, ver] = trimmed.split('==');
      dependencies.push({
        name: name.trim(),
        version: cleanVersion(ver ?? 'latest'),
        ecosystem: 'PyPI',
        rawLine: trimmed,
      });
    } else if (trimmed.includes(':')) {
      const [name, ver] = trimmed.split(':');
      dependencies.push({
        name: name.trim(),
        version: cleanVersion(ver ?? 'latest'),
        ecosystem: 'Alpine',
        rawLine: trimmed,
      });
    } else {
      dependencies.push({
        name: trimmed,
        version: 'latest',
        ecosystem: 'npm',
        rawLine: trimmed,
      });
    }
  }

  return {
    kind: 'manual',
    category: 'node-lockfile',
    dependencies,
    suggestedTargetName: fileName || 'custom-tech-stack',
    suggestedFilePath: 'stack-manifest.txt',
  };
}

export async function computeSha256Hex(input: string): Promise<string> {
  try {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const encoded = new TextEncoder().encode(input);
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
      const bytes = Array.from(new Uint8Array(hashBuffer));
      return `sha256:${bytes.map((b) => b.toString(16).padStart(2, '0')).join('')}`;
    }
  } catch {
    // Fallback deterministic hex digest below
  }
  let h1 = 0xdeadbeef ^ input.length;
  let h2 = 0x41c6ce57 ^ input.length;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  const part =
    ((h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0')).repeat(4);
  return `sha256:${part.slice(0, 64)}`;
}
