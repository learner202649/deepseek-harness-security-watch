/**
 * Scanner CLI: `node scripts/scan-cli.mjs <dir-or-package-name> [--json]`.
 *
 * Useful for pre-install checks and for CI, and it exercises the same code
 * path the host plugin uses.
 */
import { scanPackage } from '../lib/scan.js';
import { existsSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, resolve } from 'node:path';

const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const json = process.argv.includes('--json');
const target = args[0];

if (target === undefined) {
  console.error('usage: node scripts/scan-cli.mjs <dir|package-name> [--json]');
  process.exit(2);
}

function resolveTarget(t) {
  if (isAbsolute(t) || t.startsWith('.') || existsSync(t)) {
    return isAbsolute(t) ? t : resolve(process.cwd(), t);
  }
  const req = createRequire(resolve(process.cwd(), 'package.json'));
  return dirname(req.resolve(`${t}/package.json`));
}

const root = resolveTarget(target);
if (!existsSync(root) || !statSync(root).isDirectory()) {
  console.error(`not a directory: ${root}`);
  process.exit(2);
}

const result = scanPackage(root);
if (json) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(`package:   ${result.name ?? '?'}@${result.version ?? '?'}`);
  console.log(`verdict:   ${result.verdict}`);
  console.log(`findings:  high=${result.counts.high} medium=${result.counts.medium} low=${result.counts.low}`);
  console.log(`scanned:   ${result.fileCount} files, ${result.bytes} bytes${result.truncated ? ' (truncated)' : ''}`);
  for (const f of result.findings) {
    console.log(`  [${f.severity}] ${f.rule} ${f.title} @ ${f.file}:${f.line}`);
    console.log(`    ${f.evidence}`);
  }
}
process.exitCode = result.verdict === 'risk' ? 1 : 0;
