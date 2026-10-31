import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { inspectFile, inspectRepository } from './repository-privacy.mjs';

test('rejects common credentials without displaying them', () => {
  for (const value of [
    'ghp_' + 'a'.repeat(36),
    'github_pat_' + 'a'.repeat(50),
    'AKIA' + 'A'.repeat(16),
    'sk-proj-' + 'a'.repeat(50),
    '-----BEGIN ' + 'PRIVATE KEY-----',
    'https://' + 'name:password@example.invalid',
  ]) assert.deepEqual(inspectFile('example.md', value), ['credential-pattern']);
});

test('rejects sensitive files including nested database sidecars', () => {
  for (const filename of ['.env', '.env.local', 'nested/.env.production', 'data/private.sqlite-wal',
    'data/private.db-shm', 'secret.key', 'export.har', 'capture.pcapng', 'recordings/call.wav',
    'private-data/user.json', 'conversation-exports/session.txt']) {
    assert.deepEqual(inspectFile(filename), ['sensitive-file'], filename);
  }
});

test('allows documented examples and ordinary source links', () => {
  for (const filename of ['.env.example', 'README.md', 'case-studies/example.md']) {
    assert.deepEqual(inspectFile(filename, '[Source](https://example.invalid/article)'), []);
  }
});

test('blocks remote embeds while allowing local images', () => {
  for (const value of ['![pixel](' + 'https://example.invalid/p.gif)', '![pixel](' + '//example.invalid/p.gif)',
    '<img src="' + 'https://example.invalid/p.gif">', "<iframe src='" + "https://example.invalid'>"]) {
    assert.deepEqual(inspectFile('README.md', value), ['remote-embedded-resource']);
  }
  assert.deepEqual(inspectFile('README.md', '![Diagram](assets/diagram.png)'), []);
});

test('scans staged additions and current contents without returning matching secrets', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'repository-privacy-'));
  try {
    execFileSync('git', ['init', '-q', root]);
    writeFileSync(path.join(root, 'example.md'), 'Synthetic example');
    execFileSync('git', ['add', 'example.md'], { cwd: root });
    const secret = 'ghp_' + 'z'.repeat(36);
    writeFileSync(path.join(root, 'example.md'), secret);
    const result = inspectRepository(root);
    assert.deepEqual(result.findings, [{ filename: 'example.md', rule: 'credential-pattern' }]);
    assert.equal(result.checkedFiles, 1);
    assert.equal(JSON.stringify(result).includes(secret), false);
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(tmpdir()));
    assert.equal(path.basename(root).startsWith('repository-privacy-'), true);
    rmSync(root, { recursive: true, force: true });
  }
});
