import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { resolvePackageRoot } from '../lib/resolve.js';

const root = mkdtempSync(join(tmpdir(), 'dsh-sw-resolve-'));
const scoped = join(root, 'node_modules', '@scope', 'pkg');
const plain = join(root, 'node_modules', 'plain');
mkdirSync(scoped, { recursive: true });
mkdirSync(plain, { recursive: true });
writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'profile', private: true }));
// A package that exports only "." and hides ./package.json, like real
// third-party plugins do (this is what broke @tencent-connect/dsh-qqbot).
writeFileSync(
  join(scoped, 'package.json'),
  JSON.stringify({
    name: '@scope/pkg',
    version: '1.0.0',
    type: 'module',
    exports: { '.': { import: './index.mjs' } },
  }),
);
writeFileSync(join(scoped, 'index.mjs'), 'export const x = 1;\n');
writeFileSync(join(plain, 'package.json'), JSON.stringify({ name: 'plain', main: 'index.js' }));
writeFileSync(join(plain, 'index.js'), 'module.exports = 1;\n');

const requireFromProfile = createRequire(join(root, 'package.json'));
const resolveFromProfile = (spec) => requireFromProfile.resolve(spec);

test.after(() => rmSync(root, { recursive: true, force: true }));

test('the exports map really hides ./package.json', () => {
  assert.throws(
    () => resolveFromProfile('@scope/pkg/package.json'),
    (error) => error.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  );
});

test('resolves a package whose exports hide ./package.json', () => {
  assert.equal(resolvePackageRoot(root, '@scope/pkg', resolveFromProfile), scoped);
});

test('resolves a plain package from the installed layout', () => {
  assert.equal(resolvePackageRoot(root, 'plain', resolveFromProfile), plain);
});

test('resolves the profile directory itself for a relative entry', () => {
  assert.equal(resolvePackageRoot(root, '.', resolveFromProfile), root);
});

test('returns undefined for a package that is not installed', () => {
  assert.equal(resolvePackageRoot(root, 'not-installed', resolveFromProfile), undefined);
});

test('returns undefined for a name that is not a package', () => {
  assert.equal(resolvePackageRoot(root, 'a bad name!', resolveFromProfile), undefined);
});
