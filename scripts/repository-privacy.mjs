import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Heuristics catch common publication mistakes; they do not establish absence of secrets.
export function inspectFile(filename, content = '') {
  const findings = [];
  const normalized = filename.replaceAll('\\', '/');
  const basename = normalized.split('/').at(-1);
  if ((/^\.env(?:\.|$)/i.test(basename) && basename !== '.env.example') ||
      /\.(?:sqlite3?|db)(?:-(?:wal|shm|journal))?$/i.test(basename) ||
      /\.(?:pem|key|p12|pfx|har|pcapng?)$/i.test(basename) ||
      /(?:^|\/)(?:private-data|conversation-exports|recordings)(?:\/|$)/i.test(normalized)) {
    findings.push('sensitive-file');
  }
  const credentials = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
    /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/,
    /https?:\/\/[^\s/@:]+:[^\s/@]+@/i,
  ];
  if (credentials.some(pattern => pattern.test(content))) findings.push('credential-pattern');
  // Readers should deliberately follow a link before contacting another service.
  if (/!\[[^\]]*\]\(\s*(?:https?:)?\/\//i.test(content) ||
      /<(?:img|iframe|script|video|audio|source)\b[^>]*\b(?:src|srcset)\s*=\s*["'](?:https?:)?\/\//i.test(content)) {
    findings.push('remote-embedded-resource');
  }
  return findings;
}

export function inspectRepository(root) {
  const filenames = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean);
  const findings = [];
  let binaryFiles = 0;
  for (const filename of filenames) {
    if (lstatSync(path.join(root, filename)).isSymbolicLink()) {
      findings.push({ filename, rule: 'unsafe-symlink' });
      continue;
    }
    const bytes = readFileSync(path.join(root, filename));
    const isBinary = bytes.includes(0) || /\.(?:pdf|png|jpe?g|gif|webp|zip)$/i.test(filename);
    if (isBinary) binaryFiles++;
    for (const rule of inspectFile(filename, isBinary ? '' : bytes.toString('utf8'))) {
      // Never echo matching content, which may contain the sensitive material.
      findings.push({ filename, rule });
    }
  }
  return { findings, checkedFiles: filenames.length, binaryFiles };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
  const result = inspectRepository(root);
  for (const finding of result.findings) console.error(JSON.stringify(finding));
  console.log(`Checked ${result.checkedFiles} tracked files; ${result.binaryFiles} binary files require manual content review.`);
  process.exitCode = result.findings.length ? 1 : 0;
}
