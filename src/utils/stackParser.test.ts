import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  computeSha256Hex,
  detectManifestKind,
  parseTechStack,
  SAMPLE_MANIFESTS,
} from './stackParser.js';

test('detectManifestKind identifies manifest types by filename and content', () => {
  assert.equal(detectManifestKind('', 'package.json'), 'package.json');
  assert.equal(detectManifestKind('', 'requirements.txt'), 'requirements.txt');
  assert.equal(detectManifestKind('', 'go.mod'), 'go.mod');
  assert.equal(detectManifestKind('', 'Dockerfile'), 'Dockerfile');

  assert.equal(detectManifestKind('{\n  "name": "app"\n}'), 'package.json');
  assert.equal(detectManifestKind('FROM alpine:3.18\nRUN apk add curl'), 'Dockerfile');
  assert.equal(detectManifestKind('module github.com/acme/app\nrequire ( golang.org/x/net v0.16.0 )'), 'go.mod');
  assert.equal(detectManifestKind('django==3.2.18\nurllib3==1.26.17'), 'requirements.txt');
  assert.equal(detectManifestKind('express@4.18.2'), 'manual');
});

test('parseTechStack parses package.json including devDependencies and optionalDependencies', () => {
  const jsonContent = JSON.stringify({
    name: 'test-service',
    version: '1.0.0',
    dependencies: {
      express: '4.18.2',
    },
    devDependencies: {
      typescript: '5.0.4',
    },
    optionalDependencies: {
      fsevents: '2.3.2',
    },
  });

  const result = parseTechStack(jsonContent, 'package.json', 'services/test-service/package.json');
  assert.equal(result.kind, 'package.json');
  assert.equal(result.category, 'node-lockfile');
  assert.equal(result.suggestedTargetName, 'test-service/package.json');
  assert.equal(result.dependencies.length, 3);

  const deps = result.dependencies;
  assert.equal(deps[0].name, 'express');
  assert.equal(deps[0].version, '4.18.2');
  assert.equal(deps[0].ecosystem, 'npm');

  assert.equal(deps[1].name, 'typescript');
  assert.equal(deps[1].version, '5.0.4');

  assert.equal(deps[2].name, 'fsevents');
  assert.equal(deps[2].version, '2.3.2');
});

test('parseTechStack parses python requirements.txt with comments, extras, and version specifiers', () => {
  const reqContent = `
# Core dependencies
django==3.2.18
urllib3>=1.26.17 # HTTP client
requests[security]==2.31.0
-r base.txt
`;

  const result = parseTechStack(reqContent, 'requirements.txt', 'ml/requirements.txt');
  assert.equal(result.kind, 'requirements.txt');
  assert.equal(result.category, 'python-wheel');
  assert.equal(result.dependencies.length, 3);

  const names = result.dependencies.map((d) => d.name);
  assert.deepEqual(names, ['django', 'urllib3', 'requests']);
  assert.equal(result.dependencies[0].version, '3.2.18');
  assert.equal(result.dependencies[1].version, '1.26.17');
  assert.equal(result.dependencies[2].version, '2.31.0');
});

test('parseTechStack parses go.mod files', () => {
  const result = parseTechStack(SAMPLE_MANIFESTS['go.mod'].content, 'go.mod');
  assert.equal(result.kind, 'go.mod');
  assert.equal(result.category, 'go-module');
  assert.equal(result.suggestedTargetName, 'edge-router/go.mod');
  assert.ok(result.dependencies.length >= 4);

  const netDep = result.dependencies.find((d) => d.name === 'golang.org/x/net');
  assert.ok(netDep);
  assert.equal(netDep?.version, '0.16.0');
  assert.equal(netDep?.ecosystem, 'Go');
});

test('parseTechStack parses Dockerfiles for base image and packages', () => {
  const result = parseTechStack(SAMPLE_MANIFESTS['Dockerfile'].content, 'Dockerfile');
  assert.equal(result.kind, 'Dockerfile');
  assert.equal(result.category, 'container');
  assert.equal(result.suggestedTargetName, 'alpine:3.18');
  assert.ok(result.dependencies.length >= 3);

  const runcDep = result.dependencies.find((d) => d.name === 'runc');
  assert.ok(runcDep);
  assert.equal(runcDep?.version, '1.1.11');
  assert.equal(runcDep?.ecosystem, 'Alpine');
});

test('parseTechStack parses Java Maven pom.xml and Gradle build.gradle files', () => {
  const pomResult = parseTechStack(SAMPLE_MANIFESTS['pom.xml'].content, 'pom.xml', 'services/billing/pom.xml');
  assert.equal(pomResult.kind, 'pom.xml');
  assert.equal(pomResult.category, 'java-maven');
  assert.ok(pomResult.dependencies.length >= 3);

  const log4jDep = pomResult.dependencies.find((d) => d.name === 'log4j-core');
  assert.ok(log4jDep);
  assert.equal(log4jDep?.version, '2.14.1');
  assert.equal(log4jDep?.ecosystem, 'Maven');

  const gradleResult = parseTechStack(SAMPLE_MANIFESTS['build.gradle'].content, 'build.gradle', 'services/auth/build.gradle');
  assert.equal(gradleResult.kind, 'build.gradle');
  assert.equal(gradleResult.category, 'java-maven');
  assert.ok(gradleResult.dependencies.length >= 3);
});

test('computeSha256Hex generates consistent deterministic SHA-256 hash', async () => {
  const hash1 = await computeSha256Hex('stackguard-test-input');
  const hash2 = await computeSha256Hex('stackguard-test-input');
  assert.ok(hash1.startsWith('sha256:'));
  assert.equal(hash1, hash2);
  assert.equal(hash1.length, 71); // sha256: + 64 hex chars
});
