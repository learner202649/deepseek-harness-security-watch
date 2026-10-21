/**
 * Bounded directory scanner for dsh-security-watch.
 *
 * The mount-time path must never stall the host: every limit here is a hard
 * stop, and hitting one is recorded in `truncated` rather than silently
 * pretending the package is clean.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { scanFile, scanManifest, summarize } from './rules.js';

// Only VCS metadata and installed dependencies are skipped. Build output
// (`dist/`, `build/`, `out/`) is deliberately scanned: for published packages
// that IS the shipped code, and skipping it produced blind spots.
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);
const TEXT_EXT = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.json', '.md', '.mdx', '.yml', '.yaml', '.sh', '.ps1', '.bash', '.zsh',
]);

/**
 * @param {string} root absolute package directory
 * @param {{ maxFiles?: number, maxFileBytes?: number, maxTotalBytes?: number }} [limits]
 */
export function scanPackage(root, limits = {}) {
  const maxFiles = limits.maxFiles ?? 2000;
  const maxFileBytes = limits.maxFileBytes ?? 2 * 1024 * 1024;
  const maxTotalBytes = limits.maxTotalBytes ?? 32 * 1024 * 1024;

  const files = [];
  let bytes = 0;
  let truncated = false;
  const seen = new Set();

  const walk = (dir) => {
    if (files.length >= maxFiles || bytes >= maxTotalBytes) {
      truncated = true;
      return;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      truncated = true;
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= maxFiles || bytes >= maxTotalBytes) {
        truncated = true;
        return;
      }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.') && entry.name !== '.dsh') continue;
        walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = extOf(entry.name);
      if (!TEXT_EXT.has(ext) && entry.name !== 'package.json') continue;
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.size > maxFileBytes) {
        truncated = true;
        continue;
      }
      if (bytes + st.size > maxTotalBytes) {
        truncated = true;
        continue;
      }
      let content;
      try {
        content = readFileSync(full, 'utf8');
      } catch {
        continue;
      }
      // Cheap binary gate: NUL bytes or too many replacement chars.
      if (content.indexOf('\u0000') !== -1) continue;
      const rel = relative(root, full).split(sep).join('/');
      const key = rel.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      bytes += st.size;
      files.push({ rel, content });
    }
  };

  walk(root);

  const findings = [];
  let pkgJson = null;
  const pkgFile = files.find((f) => f.rel === 'package.json');
  if (pkgFile !== undefined) {
    try {
      pkgJson = JSON.parse(pkgFile.content);
    } catch {
      pkgJson = null;
    }
  }
  if (pkgJson !== null) findings.push(...scanManifest('package.json', pkgJson));
  for (const f of files) {
    if (f.rel === 'package.json') continue;
    const isFixture = /^(?:test|tests|__tests__|fixtures|examples)\//.test(f.rel);
    for (const finding of scanFile(f.rel, f.content)) {
      // Test fixtures deliberately contain dangerous-looking strings. Keep
      // them visible, but never let a fixture escalate the package verdict.
      findings.push(isFixture ? { ...finding, severity: 'low', title: `${finding.title} (test/fixture file)` } : finding);
    }
  }

  const hash = createHash('sha256');
  for (const f of files) {
    hash.update(f.rel);
    hash.update('\u0000');
    hash.update(f.content);
    hash.update('\u0000');
  }

  const summary = summarize({ findings, fileCount: files.length, bytes, truncated });
  return {
    root,
    name: typeof pkgJson?.name === 'string' ? pkgJson.name : undefined,
    version: typeof pkgJson?.version === 'string' ? pkgJson.version : undefined,
    hash: hash.digest('hex'),
    ...summary,
  };
}

function extOf(name) {
  const i = name.lastIndexOf('.');
  return i < 0 ? '' : name.slice(i).toLowerCase();
}
