/**
 * Bounded directory scanner for dsh-security-watch.
 *
 * The mount-time path must never stall the host: every limit here is a hard
 * stop, and hitting one (or failing to read a file) is recorded rather than
 * silently pretending the package is clean.
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, readlinkSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { scanFile, scanManifest, summarize } from './rules.js';

// Only VCS metadata and installed dependencies are skipped. Build output
// (`dist/`, `build/`, `out/`) is deliberately scanned: for published packages
// that IS the shipped code, and skipping it produced blind spots.
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);
const TEXT_EXT = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.json', '.jsonc', '.json5',
  '.md', '.mdx', '.txt', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.env',
  '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.psd1', '.bat', '.cmd',
  '.html', '.htm', '.vue', '.svelte', '.astro',
]);
const MANIFEST_NAMES = new Set(['package.json']);
const EXTRA_MANIFESTS = new Set(['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock']);
const MAX_DEPTH = 40;
/** Binary files up to this size are hashed, so a swapped payload changes the hash. */
const BINARY_HASH_LIMIT = 256 * 1024;

/**
 * @param {string} root absolute package directory
 * @param {{ maxFiles?: number, maxFileBytes?: number, maxTotalBytes?: number }} [limits]
 */
export function scanPackage(root, limits = {}) {
  const maxFiles = limits.maxFiles ?? 2000;
  const maxFileBytes = limits.maxFileBytes ?? 2 * 1024 * 1024;
  const maxTotalBytes = limits.maxTotalBytes ?? 32 * 1024 * 1024;

  /** Text files that the rules inspect. */
  const textFiles = [];
  /** Every regular file, for a hash that also covers binaries and ignored extensions. */
  const hashed = [];
  let bytes = 0;
  let truncated = false;
  let unreadable = 0;
  const symlinkEscapes = [];
  const seenRel = new Set();

  const noteFile = (rel, size, digest) => {
    if (!seenRel.has(rel)) {
      seenRel.add(rel);
      hashed.push({ rel, size, digest });
    }
  };

  const walk = (dir, depth) => {
    if (filesBudget()) return;
    if (depth > MAX_DEPTH) {
      truncated = true;
      return;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      unreadable += 1;
      truncated = true;
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (filesBudget()) return;
      const full = join(dir, entry.name);
      const rel = relative(root, full).split(sep).join('/');
      if (entry.isSymbolicLink()) {
        // Never follow links: a package that links outside its own tree can
        // make the host read arbitrary files at runtime.
        try {
          const target = resolve(dir, readlinkSync(full));
          const outside = target !== root && !target.startsWith(root + sep);
          if (outside) symlinkEscapes.push({ rel, target });
        } catch {
          unreadable += 1;
        }
        continue;
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name.startsWith('.') && entry.name !== '.dsh') continue;
        walk(full, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      let st;
      try {
        st = statSync(full);
      } catch {
        unreadable += 1;
        truncated = true;
        continue;
      }
      const ext = extOf(entry.name);
      const isText = TEXT_EXT.has(ext) || MANIFEST_NAMES.has(entry.name) || EXTRA_MANIFESTS.has(entry.name);
      if (hashed.length >= maxFiles) {
        truncated = true;
        return;
      }
      if (bytes + st.size > maxTotalBytes) {
        truncated = true;
        return;
      }
      bytes += st.size;
      let digest = null;
      let text = null;
      const hashedContent = st.size <= maxFileBytes && (isText || st.size <= BINARY_HASH_LIMIT);
      if (hashedContent) {
        try {
          const raw = readFileSync(full);
          digest = createHash('sha256').update(raw).digest('hex');
          if (isText) text = decodeText(raw);
        } catch {
          unreadable += 1;
          truncated = true;
        }
      }
      noteFile(rel, st.size, digest);
      if (text === null) continue;
      // Cheap binary gate: NUL bytes mean the text decode is unreliable.
      if (text.indexOf('\u0000') !== -1) continue;
      textFiles.push({ rel, content: text });
    }
  };

  const filesBudget = () => hashed.length >= maxFiles || bytes >= maxTotalBytes;

  walk(root, 0);
  if (hashed.length >= maxFiles || bytes >= maxTotalBytes) truncated = true;

  const findings = [];
  let pkgJson = null;
  const pkgFile = textFiles.find((f) => f.rel === 'package.json');
  if (pkgFile !== undefined) {
    try {
      pkgJson = JSON.parse(pkgFile.content);
    } catch {
      pkgJson = null;
    }
  }
  if (pkgJson !== null) findings.push(...scanManifest('package.json', pkgJson));
  // Scanning the watcher itself matches the watcher's own rule table and hint
  // strings; the self-referential rules are skipped for this package only.
  const self = typeof pkgJson?.name === 'string' && pkgJson.name === 'dsh-security-watch';
  for (const f of textFiles) {
    if (f.rel === 'package.json' || EXTRA_MANIFESTS.has(f.rel)) continue;
    const isFixture = /^(?:test|tests|__tests__|fixtures|examples)\//.test(f.rel);
    for (const finding of scanFile(f.rel, f.content, { self })) {
      // Test fixtures deliberately contain dangerous-looking strings. Keep
      // them visible, but never let a fixture escalate the package verdict.
      findings.push(isFixture ? { ...finding, severity: 'low', title: `${finding.title} (test/fixture file)` } : finding);
    }
  }
  if (symlinkEscapes.length > 0) {
    findings.push({
      rule: 'R15-symlink-escape',
      severity: 'medium',
      category: 'integrity',
      title: 'Contains a symlink that points outside the package',
      file: symlinkEscapes[0].rel,
      line: 1,
      count: symlinkEscapes.length,
      evidence: `links: ${symlinkEscapes.map((l) => `${l.rel} -> ${l.target}`).join(', ').slice(0, 160)}`,
    });
  }
  if (unreadable > 0) {
    findings.push({
      rule: 'R16-scan-incomplete',
      severity: 'low',
      category: 'integrity',
      title: 'Some files could not be read, so the scan is incomplete',
      file: 'package.json',
      line: 1,
      count: unreadable,
      evidence: `${unreadable} file(s) unreadable`,
    });
  }

  const hash = createHash('sha256');
  for (const f of hashed.slice().sort((a, b) => a.rel.localeCompare(b.rel))) {
    hash.update(f.rel);
    hash.update('\u0000');
    hash.update(f.digest ?? `size:${String(f.size)}`);
    hash.update('\u0000');
  }

  const summary = summarize({
    findings,
    fileCount: hashed.length,
    bytes,
    truncated,
    incomplete: truncated || unreadable > 0 || symlinkEscapes.length > 0,
  });
  return {
    root,
    name: typeof pkgJson?.name === 'string' ? pkgJson.name : undefined,
    version: typeof pkgJson?.version === 'string' ? pkgJson.version : undefined,
    hash: hash.digest('hex'),
    ...summary,
  };
}

/** Decode UTF-8, or UTF-16 with a BOM (PowerShell often writes UTF-16LE). */
function decodeText(buffer) {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
    return buffer.subarray(2).toString('utf16le');
  }
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const swapped = Buffer.from(buffer.subarray(2));
    swapped.swap16();
    return swapped.toString('utf16le');
  }
  return buffer.toString('utf8');
}

function extOf(name) {
  const i = name.lastIndexOf('.');
  return i < 0 ? '' : name.slice(i).toLowerCase();
}
