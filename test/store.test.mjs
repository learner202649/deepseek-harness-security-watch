import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The store reads DSH_HOME lazily on every call, so setting it before use is
// enough; no module cache problem.
const home = mkdtempSync(join(tmpdir(), 'sw-home-'));
process.env.DSH_HOME = home;

const store = await import('../lib/store.js');
const { isIgnored } = await import('../lib/rules.js');

test('record, persist, and render a report', () => {
  const state = store.emptyState();
  store.recordScan(state, 'evil-plugin', {
    version: '1.0.0',
    root: '/tmp/evil',
    hash: 'deadbeef',
    verdict: 'risk',
    counts: { high: 1, medium: 0, low: 0 },
    capabilities: ['R01-exec'],
    findings: [
      { rule: 'R01-exec', severity: 'high', category: 'execution', title: 'Spawns processes', file: 'lib/x.js', line: 3, count: 1, evidence: 'execSync(' },
    ],
    fileCount: 1,
    bytes: 10,
    truncated: false,
  });
  store.saveState(state);

  const report = readFileSync(join(home, 'security-watch', 'report.md'), 'utf8');
  assert.match(report, /evil-plugin@1\.0\.0/);
  assert.match(report, /R01-exec/);

  const reloaded = store.loadState();
  assert.equal(reloaded.plugins['evil-plugin'].verdict, 'risk');
  assert.equal(store.pendingRisks(reloaded).length, 1);

  const pending = store.renderPending(reloaded);
  assert.match(pending, /need a decision/);
});

test('ignore expires when the artifact changes', () => {
  const state = store.loadState();
  store.setIgnore(state, 'evil-plugin', 'accepted for testing');
  store.saveState(state);
  assert.equal(isIgnored(state, 'evil-plugin', state.plugins['evil-plugin']), true);

  store.recordScan(state, 'evil-plugin', {
    version: '1.0.1',
    root: '/tmp/evil',
    hash: 'cafebabe',
    verdict: 'risk',
    counts: { high: 1, medium: 0, low: 0 },
    capabilities: ['R01-exec'],
    findings: [],
    fileCount: 1,
    bytes: 10,
    truncated: false,
  });
  assert.equal(isIgnored(state, 'evil-plugin', state.plugins['evil-plugin']), false);
  assert.equal(store.pendingRisks(state).length, 1);
});

test('ad-hoc directory scans never count as pending plugin risks', () => {
  const state = {
    version: 1,
    plugins: { 'C:\\tmp\\some-package': { verdict: 'risk', counts: { high: 2, medium: 0, low: 0 }, findings: [], hash: 'h2' } },
    ignores: {},
    disabled: {},
  };
  assert.equal(store.pendingRisks(state).length, 0);
  assert.equal(store.forgetRecord(state, 'C:\\tmp\\some-package'), true);
  assert.equal(state.plugins['C:\\tmp\\some-package'], undefined);
});

test('disabling resolves a recorded risk until re-enabled', () => {
  const state = {
    version: 1,
    plugins: { 'p': { verdict: 'risk', counts: { high: 1, medium: 0, low: 0 }, findings: [], hash: 'h1' } },
    ignores: {},
    disabled: {},
  };
  assert.equal(store.pendingRisks(state).length, 1);
  store.setDisabled(state, 'p', 'plugin disabled');
  assert.equal(store.pendingRisks(state).length, 0);
  assert.equal(store.clearDisabled(state, 'p'), true);
  assert.equal(store.pendingRisks(state).length, 1);
});

test.after(() => {
  rmSync(home, { recursive: true, force: true });
  assert.equal(existsSync(home), false);
});
