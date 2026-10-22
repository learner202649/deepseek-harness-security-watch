/**
 * State for dsh-security-watch: last scan per package, human decisions, and
 * the rendered report. Everything is plain JSON under
 * $DSH_HOME/security-watch/<profile> so profiles never share decisions.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { isIgnored, isPluginName, renderReport } from './rules.js';

const STATE_FILE = 'state.json';
const REPORT_FILE = 'report.md';

/** Profile name whose state this process reads and writes (undefined = legacy shared root). */
let profileKey;

/** Point the store at one profile's namespace. Pass nothing to reset (tests/legacy). */
export function configureStore(profileDir) {
  profileKey = typeof profileDir === 'string' && profileDir.length > 0
    ? basename(profileDir).replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^[-.]+/, '') || 'default'
    : undefined;
}

function dshHome() {
  return process.env.DSH_HOME && process.env.DSH_HOME.trim() !== '' ? process.env.DSH_HOME : join(homedir(), '.dsh');
}

export function storeRoot() {
  const base = join(dshHome(), 'security-watch');
  return profileKey === undefined ? base : join(base, profileKey);
}

/** Pre-0.1.5 layout: one shared state for every profile. */
function legacyRoot() {
  return join(dshHome(), 'security-watch');
}

/** Which profile already claimed the legacy shared state (if any). */
function legacyOwner() {
  try {
    const parsed = JSON.parse(readFileSync(join(legacyRoot(), 'legacy-imported.json'), 'utf8'));
    return typeof parsed?.profile === 'string' ? parsed.profile : undefined;
  } catch {
    return undefined;
  }
}

function claimLegacy(profile) {
  try {
    ensureDir(legacyRoot());
    writeFileSync(join(legacyRoot(), 'legacy-imported.json'), JSON.stringify({ profile, at: Date.now() }), { mode: 0o600 });
  } catch {
    // Best effort: a read-only home must not break loading.
  }
}

export function emptyState() {
  return { version: 1, plugins: {}, ignores: {}, disabled: {}, updatedAt: 0 };
}

export function loadState() {
  const file = join(storeRoot(), STATE_FILE);
  const legacy = join(legacyRoot(), STATE_FILE);
  const candidates = [file];
  if (profileKey !== undefined && legacy !== file && legacyOwner() === undefined) candidates.push(legacy);
  for (const candidate of candidates) {
    const parsed = readStateFile(candidate);
    if (parsed !== undefined) {
      if (profileKey !== undefined && candidate === legacy) claimLegacy(profileKey);
      return parsed;
    }
  }
  return emptyState();
}

function readStateFile(file) {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    if (parsed !== null && typeof parsed === 'object' && parsed.version === 1) {
      return { ...emptyState(), ...parsed, plugins: parsed.plugins ?? {}, ignores: parsed.ignores ?? {}, disabled: parsed.disabled ?? {} };
    }
    return undefined;
  } catch {
    // Try the last good copy, then give up and start clean rather than throw.
  }
  const backup = readStateFileRaw(`${file}.bak`);
  if (backup !== undefined) return backup;
  return undefined;
}

function readStateFileRaw(file) {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    if (parsed !== null && typeof parsed === 'object' && parsed.version === 1) {
      return { ...emptyState(), ...parsed, plugins: parsed.plugins ?? {}, ignores: parsed.ignores ?? {}, disabled: parsed.disabled ?? {} };
    }
  } catch {
    // Corrupt backup: ignore.
  }
  return undefined;
}

export function saveState(state) {
  const root = storeRoot();
  ensureDir(root);
  state.updatedAt = Date.now();
  const file = join(root, STATE_FILE);
  // Keep one previous copy so a crash during the next write cannot erase every
  // decision the operator made.
  if (existsSync(file)) {
    try {
      copyFileSync(file, `${file}.bak`);
    } catch {
      // Best effort only.
    }
  }
  atomicWrite(file, JSON.stringify(state, null, 2));
  atomicWrite(join(root, REPORT_FILE), renderReport(state));
}

/** Record one scan; returns the previous record when a real change happened. */
export function recordScan(state, name, result, now = Date.now()) {
  const prev = state.plugins[name];
  state.plugins[name] = {
    version: result.version,
    root: result.root,
    hash: result.hash,
    verdict: result.verdict,
    counts: result.counts,
    capabilities: result.capabilities,
    findings: result.findings,
    fileCount: result.fileCount,
    bytes: result.bytes,
    truncated: result.truncated,
    incomplete: result.incomplete === true,
    scannedAt: now,
  };
  return prev;
}

/** Bind an ignore decision to the artifact hash that was audited. */
export function setIgnore(state, name, reason, rule) {
  const rec = state.plugins[name];
  const hash = rec?.hash;
  const entry = { reason: String(reason || 'ignored by operator'), at: Date.now(), hash };
  if (rule !== undefined) entry.rule = String(rule);
  state.ignores[name] = entry;
  return entry;
}

export function setDisabled(state, name, reason) {
  state.disabled = state.disabled ?? {};
  state.disabled[name] = { reason: String(reason || 'disabled by operator'), at: Date.now(), hash: state.plugins[name]?.hash };
  delete state.ignores[name];
}

/** The plugin is on again: its old risk no longer counts as resolved. */
export function clearDisabled(state, name) {
  if (state.disabled?.[name] !== undefined) {
    delete state.disabled[name];
    return true;
  }
  return false;
}

/** Human-facing one-liner list for the model to relay. */
export function pendingRisks(state) {
  return Object.entries(state.plugins)
    .filter(
      ([name, rec]) =>
        isPluginName(name) &&
        rec.verdict !== 'ok' &&
        !isIgnored(state, name, rec) &&
        state.disabled?.[name] === undefined,
    )
    .map(([name, rec]) => ({ name, ...rec }))
    .sort((a, b) => (b.counts.high || 0) - (a.counts.high || 0));
}

/** Drop one record entirely (ad-hoc scans, or a decided item). */
export function forgetRecord(state, name) {
  const existed = state.plugins[name] !== undefined;
  delete state.plugins[name];
  if (state.ignores) delete state.ignores[name];
  if (state.disabled) delete state.disabled[name];
  return existed;
}

export function renderPending(state) {
  const risks = pendingRisks(state);
  if (risks.length === 0) return 'security-watch: no pending risks.';
  const lines = [`security-watch: ${risks.length} plugin(s) need a decision.`];
  for (const r of risks) {
    lines.push('');
    lines.push(`${r.name}@${r.version ?? '?'} — ${r.verdict} (high=${r.counts.high}, medium=${r.counts.medium}, low=${r.counts.low})`);
    for (const f of r.findings.slice(0, 5)) {
      lines.push(`  [${f.severity}] ${f.rule} ${f.title} @ ${f.file}:${f.line}`);
      lines.push(`    ${f.evidence}`);
    }
    if (r.findings.length > 5) lines.push(`  … ${r.findings.length - 5} more (see report.md)`);
    lines.push(`  Decide: security_watch_ignore({plugin:"${r.name}", reason:"why"}) or security_watch_disable({plugin:"${r.name}"})`);
  }
  return lines.join('\n');
}

export function ensureDir(dir) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function atomicWrite(file, content) {
  const tmp = `${file}.tmp.${process.pid}`;
  writeFileSync(tmp, content, { mode: 0o600 });
  renameSync(tmp, file);
}
