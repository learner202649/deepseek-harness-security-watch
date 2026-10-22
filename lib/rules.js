/**
 * Static rule engine for dsh-security-watch.
 *
 * Pure functions only: no fs, no ctx, no timers. `scanPackage` receives an
 * already-materialized file list, which keeps the rules unit-testable and
 * keeps the mount-time path free of hidden I/O.
 *
 * Design notes (borrowed from the plugins we audited):
 *  - Rules are *capability-shaped*, not string-shaped: "this file can spawn a
 *    process" beats "this file contains the word spawn". Where a capability
 *    only matters in a context (writing a credential file, writing a login
 *    file), the regex binds the call to the target.
 *  - Every rule carries a stable id so an ignore decision can bind to it.
 *  - Severity is deliberately blunt. The goal is a human triage list, not a
 *    probability score that nobody can act on.
 */

/** @typedef {{ id: string, severity: 'high'|'medium'|'low', category: string, title: string }} RuleMeta */

/** @type {Array<RuleMeta & { re: RegExp, on?: 'js'|'text' }>} */
export const RULES = [
  {
    id: 'R01-exec',
    severity: 'high',
    category: 'execution',
    title: 'Spawns processes (child_process / exec / spawn)',
    re: /(?:require\s*\(\s*['"](?:node:)?child_process['"]|from\s+['"](?:node:)?child_process['"]|\bexecSync\s*\(|\bspawnSync\s*\(|\bexecFileSync\s*\(|\bspawn\s*\(\s*['"`]|\bexec\s*\(\s*['"`])/g,
    on: 'js',
  },
  {
    id: 'R02-dynamic-exec',
    severity: 'high',
    category: 'execution',
    title: 'Evaluates code at runtime (eval / new Function / vm)',
    re: /\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.run(?:InNewContext|InThisContext|InContext)?\s*\(/g,
    on: 'js',
  },
  {
    id: 'R03-network',
    severity: 'medium',
    category: 'network',
    title: 'Makes outbound network calls',
    re: /\bfetch\s*\(\s*['"`]https?:|https?\.request\s*\(|\bnet\.connect\s*\(|\bnew\s+WebSocket\s*\(/g,
    on: 'js',
  },
  {
    id: 'R04-remote-payload',
    severity: 'high',
    category: 'network',
    title: 'Combines remote fetch with dynamic execution (staged payload)',
    // Both signals must appear in the same file.
    re: /fetch\s*\([\s\S]{0,400}(?:eval\s*\(|\beval\b|new\s+Function\s*\(|atob\s*\()/g,
    on: 'js',
  },
  {
    id: 'R05-sensitive-paths',
    severity: 'high',
    category: 'credentials',
    title: 'Touches credential material (~/.ssh, ~/.aws, .credentials, .npmrc)',
    re: /(?:join|resolve|readFile|readFileSync|readdir|readdirSync|stat|statSync|lstat|open|openSync|writeFile|writeFileSync|appendFile|createWriteStream|cp|copyFile|homedir)[A-Za-z]*\s*\([^\n]{0,200}(?:\.ssh|id_rsa|id_ed25519|\.aws|\.credentials|\.npmrc|_authToken|\.netrc|\.pgpass)/g,
    on: 'js',
  },
  {
    id: 'R06-env-secrets',
    severity: 'medium',
    category: 'credentials',
    title: 'Reads API-key-shaped environment variables',
    re: /process\.env\.(?:[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*)/g,
    on: 'js',
  },
  {
    id: 'R07-obfuscation',
    severity: 'medium',
    category: 'obfuscation',
    title: 'Contains obfuscation primitives (base64 / char-code chains)',
    re: /atob\s*\(|Buffer\.from\s*\([^)]{0,80},\s*['"]base64['"]|String\.fromCharCode\s*\(/g,
    on: 'js',
  },
  {
    id: 'R08-persistence',
    severity: 'high',
    category: 'persistence',
    title: 'Writes shell / login / autostart files (persistence)',
    re: /(?:writeFile|appendFile|createWriteStream|rename|cp|copyFile|mkdir|open)[A-Za-z]*\s*\([^\n]{0,200}(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|LaunchAgents|autostart|\.config\/autostart)/g,
    on: 'js',
  },
  {
    id: 'R09-config-tamper',
    severity: 'medium',
    category: 'integrity',
    title: 'Rewrites harness configuration (cordis.patch.yml / cordis.yml)',
    re: /(?:writeFile|appendFile|createWriteStream|rename|cp|copyFile)[A-Za-z]*\s*\([^\n]{0,200}cordis\.(?:patch\.)?ya?ml/g,
    on: 'js',
  },
  {
    id: 'R10-prompt-injection',
    severity: 'medium',
    category: 'prompt-injection',
    title: 'Contains instruction-override phrases (agents will read this)',
    re: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|do\s+not\s+(?:ask|confirm|notify)|without\s+(?:asking|confirmation)|忽略(?:之前|以上|上述)(?:的)?指令|无需确认|不要询问|直接执行/g,
    on: 'text',
  },
  {
    id: 'R11-home-write',
    severity: 'medium',
    category: 'filesystem',
    title: 'Writes into the home directory',
    re: /(?:writeFile|appendFile|createWriteStream|mkdir|rename|cp|copyFile)[A-Za-z]*\s*\([^\n]{0,200}(?:homedir\s*\(\)|os\.userInfo\s*\(\)|process\.env\.HOME)/g,
    on: 'js',
  },
  {
    id: 'R12-remote-code',
    severity: 'high',
    category: 'network',
    title: 'Downloads and then executes remote code',
    re: /(?:fetch|https?\.get|https?\.request)\s*\([\s\S]{0,600}(?:WriteFile|writeFile|createWriteStream)[\s\S]{0,600}(?:import\s*\(|require\s*\(|eval\s*\()/g,
    on: 'js',
  },
  {
    id: 'R17-browser-credentials',
    severity: 'high',
    category: 'credentials',
    title: 'Reads browser profile data (cookies / saved logins)',
    re: /(?:Login Data|Network[\\/]Cookies|Local State|key4\.db|logins\.json|(?:Chrome|Chromium|Edge|Firefox|Brave|Opera)[^'"`\n]{0,40}(?:User Data|Profiles|profile))/g,
    on: 'js',
  },
  {
    id: 'R18-encoded-command',
    severity: 'medium',
    category: 'execution',
    title: 'Launches an encoded or hidden command shell',
    re: /(?:powershell|pwsh)(?:\.exe)?[^\n]{0,120}-(?:enc|encodedcommand)\b|\bcmd(?:\.exe)?\s+\/c[^\n]{0,80}-w(?:indowstyle)?\s+hidden|CreateNoWindow\s*=\s*true/gi,
    on: 'js',
  },
  {
    id: 'R19-watcher-tamper',
    severity: 'medium',
    category: 'integrity',
    title: 'Touches the security-watch state or its decisions',
    re: /security_watch_(?:ignore|disable|forget)\s*\(|security[-_ ]?watch[\\/](?:state|report)\.(?:json|md)/gi,
    on: 'js',
  },
];

/** Severity points used only to rank a backlog, never to auto-decide. */
export const SEVERITY_POINTS = { high: 10, medium: 4, low: 1 };

/** Rules that only make sense for JavaScript-ish source. */
const JS_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']);

/**
 * Rules whose patterns live in this package's own source (the rule table, the
 * popup hint strings). Scanning the watcher with them only matches the watcher
 * itself, so a self-scan skips them.
 */
const SELF_EXEMPT = new Set(['R17-browser-credentials', 'R18-encoded-command', 'R19-watcher-tamper']);

/**
 * @param {string} relPath
 * @param {string} content
 * @param {{ only?: 'js'|'text', self?: boolean }} [opts]
 * @returns {Array<{ rule: string, severity: string, category: string, title: string, file: string, line: number, count: number, evidence: string }>}
 */
export function scanFile(relPath, content, opts = {}) {
  const ext = extnameLower(relPath);
  const isJs = JS_EXT.has(ext) || opts.only === 'js';
  const findings = [];
  for (const rule of RULES) {
    if (opts.self === true && SELF_EXEMPT.has(rule.id)) continue;
    if (opts.only !== undefined && rule.on !== opts.only) continue;
    if (rule.on === 'js' && !isJs) continue;
    if (rule.on === 'text' && isJs) continue;
    const matches = collect(rule.re, content);
    if (matches.length === 0) continue;
    const first = matches[0];
    findings.push({
      rule: rule.id,
      severity: rule.severity,
      category: rule.category,
      title: rule.title,
      file: relPath,
      line: lineOf(content, first.index),
      count: matches.length,
      evidence: first.text.slice(0, 160),
    });
  }
  return findings;
}

/** Package-manifest rules: install-time execution is its own risk class. */
export function scanManifest(relPath, pkgJson) {
  const findings = [];
  const scripts = (pkgJson && pkgJson.scripts) || {};
  const lifecycle = ['preinstall', 'install', 'postinstall', 'prepare'];
  const present = lifecycle.filter((k) => typeof scripts[k] === 'string');
  if (present.length > 0) {
    findings.push({
      rule: 'R00-install-scripts',
      severity: 'high',
      category: 'supply-chain',
      title: 'Runs code at install time (lifecycle scripts)',
      file: relPath,
      line: 1,
      count: present.length,
      evidence: `scripts: ${present.join(', ')}`,
    });
  }
  if (typeof pkgJson?.dsh?.client === 'object' || typeof pkgJson?.dsh?.client === 'string') {
    findings.push({
      rule: 'R13-client-half',
      severity: 'low',
      category: 'surface',
      title: 'Ships a browser half (runs inside the GUI page)',
      file: relPath,
      line: 1,
      count: 1,
      evidence: 'dsh.client present',
    });
  }
  return findings;
}

/**
 * Aggregate a full package scan.
 * @param {{ findings: Array<ReturnType<typeof scanFile>[number]>, fileCount: number, bytes: number, truncated: boolean }} input
 */
export function summarize(input) {
  const counts = { high: 0, medium: 0, low: 0 };
  let points = 0;
  for (const f of input.findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    points += SEVERITY_POINTS[f.severity] || 0;
  }
  const incomplete = input.incomplete === true || input.truncated === true;
  // A bounded scan that could not see everything must never read as "clean":
  // an incomplete package is at least worth a look.
  const verdict = counts.high > 0 ? 'risk' : counts.medium > 0 || incomplete ? 'attention' : 'ok';
  return {
    verdict,
    counts,
    points,
    capabilities: [...new Set(input.findings.map((f) => f.rule))].sort(),
    findings: input.findings,
    fileCount: input.fileCount,
    bytes: input.bytes,
    truncated: input.truncated,
    incomplete,
  };
}

/**
 * Compare two scans of the same package across versions. A capability that
 * appears after an upgrade is the interesting signal; a whole-package verdict
 * flip is the loud one.
 */
export function diffCapabilities(before = [], after = []) {
  const a = new Set(before);
  const b = new Set(after);
  return {
    added: [...b].filter((x) => !a.has(x)).sort(),
    removed: [...a].filter((x) => !b.has(x)).sort(),
  };
}

/** Render findings for a human, not for a machine. */
export function renderReport(state) {
  const lines = [];
  lines.push('# dsh-security-watch report');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  const risky = Object.entries(state.plugins || {})
    .filter(([name, v]) => v.verdict !== 'ok' && state.disabled?.[name] === undefined)
    .sort((x, y) => pointsOf(y[1]) - pointsOf(x[1]));
  // Ad-hoc directory scans are not installed plugins: they never join the
  // pending list and are listed separately.
  const entries = risky.filter(([name]) => isPluginName(name));
  const adHoc = risky.filter(([name]) => !isPluginName(name));
  const resolved = Object.entries(state.disabled || {});
  if (entries.length === 0) {
    lines.push('No pending risks. Every scanned plugin is clean, ignored, or disabled.');
  }
  for (const [name, v] of entries) {
    const ignored = isIgnored(state, name, v);
    const partial = v.incomplete === true || v.truncated === true ? ' (scan incomplete: size limits or unreadable files)' : '';
    lines.push(`## ${name}@${v.version || '?'} — ${v.verdict}${ignored ? ' (ignored)' : ''}${partial}`);
    for (const f of v.findings) {
      lines.push(`- [${f.severity}] ${f.rule} ${f.title}`);
      lines.push(`  ${f.file}:${f.line}  ${f.evidence}`);
    }
    lines.push(`  Actions: security_watch_ignore({plugin:"${name}", reason:"..."}) or security_watch_disable({plugin:"${name}"})`);
    lines.push('');
  }
  if (adHoc.length > 0) {
    lines.push('## Ad-hoc scans (not counted as plugin risks)');
    for (const [name, v] of adHoc) {
      lines.push(`- ${name} — ${v.verdict} (${(v.findings || []).length} findings)`);
    }
    lines.push('');
  }
  if (resolved.length > 0) {
    lines.push('## Resolved by disabling');
    for (const [name, entry] of resolved) {
      lines.push(`- ${name} — ${entry.reason || 'disabled'}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

/** An npm-style package name, as opposed to an ad-hoc directory path. */
const PACKAGE_NAME_RE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;

export function isPluginName(name) {
  return typeof name === 'string' && PACKAGE_NAME_RE.test(name);
}

/** An ignore decision is bound to the audited artifact, not to the name. */
export function isIgnored(state, name, record) {
  const ig = state.ignores?.[name];
  if (ig === undefined) return false;
  if (ig.hash !== undefined && record.hash !== undefined && ig.hash !== record.hash) return false;
  return true;
}

function pointsOf(v) {
  const c = v.counts || {};
  return (c.high || 0) * 10 + (c.medium || 0) * 4 + (c.low || 0);
}

function extnameLower(p) {
  const i = p.lastIndexOf('.');
  return i < 0 ? '' : p.slice(i).toLowerCase();
}

function collect(re, text) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ index: m.index, text: m[0] });
    if (out.length >= 3) break;
    if (m.index === re.lastIndex) re.lastIndex += 1;
  }
  return out;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}
