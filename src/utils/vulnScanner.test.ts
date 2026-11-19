import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseTechStack } from './stackParser.js';
import { scanTechStack } from './vulnScanner.js';

test('scanTechStack matches local CVE catalog rules for vulnerable packages', async () => {
  const parsed = parseTechStack(
    `{
      "dependencies": {
        "runc": "1.1.11",
        "tar": "6.1.11",
        "express": "4.18.2"
      }
    }`,
    'package.json'
  );

  const output = await scanTechStack({
    targetName: 'test-app/package.json',
    filePath: 'package.json',
    category: 'node-lockfile',
    branch: 'main',
    rawContent: 'test-content',
    dependencies: parsed.dependencies,
  });

  assert.ok(output.target);
  assert.equal(output.target.name, 'test-app/package.json');
  assert.ok(output.target.digest.startsWith('sha256:'));

  const cveIds = output.vulnerabilities.map((v) => v.cveId);
  assert.ok(cveIds.includes('CVE-2024-21626')); // runc
  assert.ok(cveIds.includes('CVE-2024-28863')); // tar
  assert.ok(cveIds.includes('CVE-2024-29041')); // express

  const runcVuln = output.vulnerabilities.find((v) => v.packageName === 'runc');
  assert.ok(runcVuln);
  assert.equal(runcVuln?.severity, 'critical');
  assert.equal(runcVuln?.fixedVersion, '1.1.12');
  assert.equal(runcVuln?.isKev, true);
  assert.ok(runcVuln?.remediation.command.includes('1.1.12'));
});

test('scanTechStack ignores packages with non-vulnerable patched versions', async () => {
  const parsed = parseTechStack(
    `{
      "dependencies": {
        "runc": "1.1.12",
        "express": "4.19.2"
      }
    }`,
    'package.json'
  );

  const output = await scanTechStack({
    targetName: 'safe-app/package.json',
    filePath: 'package.json',
    category: 'node-lockfile',
    branch: 'main',
    rawContent: 'safe-content',
    dependencies: parsed.dependencies,
  });

  // Both runc 1.1.12 and express 4.19.2 are patched above max vulnerable versions
  const cveIds = output.vulnerabilities.map((v) => v.cveId);
  assert.ok(!cveIds.includes('CVE-2024-21626'));
  assert.ok(!cveIds.includes('CVE-2024-29041'));
});

test('scanTechStack safely builds remediation lines without corrupted partial string replacement', async () => {
  const parsed = parseTechStack(
    `{
      "dependencies": {
        "express": "4.18.2"
      }
    }`,
    'package.json'
  );

  const output = await scanTechStack({
    targetName: 'app/package.json',
    filePath: 'package.json',
    category: 'node-lockfile',
    branch: 'main',
    rawContent: 'content',
    dependencies: parsed.dependencies,
  });

  const expressVuln = output.vulnerabilities.find((v) => v.packageName === 'express');
  assert.ok(expressVuln);
  assert.equal(expressVuln?.remediation.removedLine, '    "express": "4.18.2",');
  assert.equal(expressVuln?.remediation.addedLine, '    "express": "4.19.2",');
});
