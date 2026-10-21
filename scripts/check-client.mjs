/**
 * Validate the browser artifact without a bundler.
 *
 * The Harness client module format is a plain script that registers a lazy
 * factory (`window.__ModuleLoader__.load({ id, factory })`), so there is
 * nothing to compile. This check fails loudly when the artifact drifts from
 * that contract, which the slot runtime would otherwise only reveal as a
 * broken entry in the page console.
 */
import { readFileSync } from 'node:fs';
import { Script } from 'node:vm';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const file = join(root, 'lib', 'client.js');
const source = readFileSync(file, 'utf8');

const problems = [];
if (!source.includes('window.__ModuleLoader__.load(')) problems.push('missing window.__ModuleLoader__.load({ id, factory })');
if (!source.includes("require('react')")) problems.push("missing require('react')");
if (!/inject:\s*\[[^\]]*'slots'/.test(source)) problems.push("missing 'slots' in inject");
if (!/inject:\s*\[[^\]]*'remote'/.test(source)) problems.push("missing 'remote' in inject");
if (!source.includes('sidebar.footer.action')) problems.push('missing sidebar.footer.action registration');

// Parse as a classic script (the artifact is not an ES module). `vm.Script`
// compiles without executing and avoids `new Function`, which the scanner
// would correctly flag as dynamic execution.
try {
  new Script(source);
} catch (error) {
  problems.push(`syntax: ${String(error && error.message ? error.message : error)}`);
}

if (problems.length > 0) {
  console.error(`client artifact check failed for ${file}:`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`client artifact ok: ${file} (${source.length} bytes)`);
