import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';

/** Package names the Loader may use: npm names, optionally scoped. */
const PACKAGE_NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;

/**
 * Resolve a Loader entry name to the package root that holds its manifest.
 *
 * A package `exports` map controls every subpath, including `./package.json`:
 * a package that exports only `.` (or an ESM-only `.`) makes
 * `require.resolve('<name>/package.json')` throw
 * `ERR_PACKAGE_PATH_NOT_EXPORTED`. The installed layout is authoritative, so
 * look under `node_modules` first and fall back to Node resolution only when
 * that misses (hoisted/alternative layouts).
 *
 * @param profileDir Directory that holds the profile `package.json` and `node_modules`.
 * @param entryName Loader entry name (package name or absolute path).
 * @param resolveFromProfile Optional `require.resolve` bound to the profile.
 * @returns The package root, or undefined when nothing resolvable matches.
 */
export function resolvePackageRoot(profileDir, entryName, resolveFromProfile) {
  if (typeof entryName !== 'string' || entryName.length === 0) return undefined;
  if (isAbsolute(entryName)) {
    return existsSync(join(entryName, 'package.json')) ? entryName : undefined;
  }
  if (entryName.startsWith('.')) {
    const dir = resolve(profileDir, entryName);
    return existsSync(join(dir, 'package.json')) ? dir : undefined;
  }
  if (!PACKAGE_NAME_RE.test(entryName)) return undefined;
  const direct = join(profileDir, 'node_modules', entryName);
  if (existsSync(join(direct, 'package.json'))) return direct;
  if (typeof resolveFromProfile !== 'function') return undefined;
  try {
    return dirname(resolveFromProfile(`${entryName}/package.json`));
  } catch {
    // The exports map may hide `./package.json`; resolve the entry point and
    // walk up to the nearest manifest instead.
  }
  try {
    let dir = dirname(resolveFromProfile(entryName));
    for (let i = 0; i < 8; i += 1) {
      const parent = dirname(dir);
      if (parent === dir) break;
      if (existsSync(join(dir, 'package.json'))) return dir;
      dir = parent;
    }
  } catch {
    // Unresolvable by every strategy.
  }
  return undefined;
}
