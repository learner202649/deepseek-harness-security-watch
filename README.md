# dsh-security-watch

Alarm-only security watch for DeepSeek Harness. It scans third-party plugin
packages **when they mount**, raises a risk report, and offers the human two
explicit actions: ignore the risk (bound to the exact artifact) or disable the
plugin. It never blocks a plugin and never changes configuration on its own.

## Why this shape

The three plugins we audited split along a useful line:

| | vet | gate | secure-audit |
|---|---|---|---|
| automatic | yes (`internal/plugin`) | no (model must call) | no |
| can block | yes, `mode: deny` | no | no |
| operates at | mount time | before install | deployment posture |

None of them does "detect → tell the human → let the human decide" as a
first-class flow. `vet` is closest, but its `deny` mode is a binary automatic
verdict, and `gate` depends on the model choosing to call it.

This plugin takes the missing shape:

1. **Automatic, non-blocking detection** at mount time.
2. **A human decision surface** instead of an automatic block.
3. **Decisions that expire**: an ignore binds to the audited artifact hash, so
   a new version or a changed tarball is re-flagged.

## Behaviour

- **Audit on enable only.** A plugin that is already on when the harness starts
  inherits trust: startup records the current bundle selection and scans
  nothing. Auditing happens on an off→on transition (detected by diffing
  `dsh.profile.bundles` on `plugin-manager/changed`) or, after the first 15
  seconds, on a live mount.
- Official `@deepseek-ai/*` packages are skipped by the static rules, but a
  newly enabled one still produces a popup that offers the LLM deep audit.
- Scans are bounded: 2000 files, 2 MiB per file, 32 MiB total, `node_modules`
  skipped. Hitting a cap sets `truncated`, never "clean".
- Findings are capability-shaped rules (exec, dynamic exec, network, staged
  payload, credential paths, env secrets, obfuscation, persistence, config
  tamper, prompt injection, home writes, remote code).
- On a new risk: one `logger.warn`, one `security-watch/risk` event, and an
  updated `report.md`.

## What the static audit covers

The deterministic scan is a set of capability-shaped rules over the plugin's
source text. Each hit carries a rule id, severity, file and line, so a decision
can be made and re-checked later.

| Rule | Severity | Detects |
|---|---|---|
| `R00-install-scripts` | high | Lifecycle scripts in `package.json`: `preinstall`, `install`, `postinstall`, `prepare` |
| `R01-exec` | high | Process spawning: `require/import('child_process')`, `execSync`, `spawnSync`, `execFileSync`, `spawn('…')`, `exec('…')` |
| `R02-dynamic-exec` | high | Runtime code evaluation: `eval(`, `new Function(`, `vm.run*` |
| `R03-network` | medium | Outbound calls: `fetch('http…')`, `http(s).request`, `net.connect`, `new WebSocket` |
| `R04-remote-payload` | high | Fetch combined with `eval`/`new Function`/`atob` in one file (staged payload) |
| `R05-sensitive-paths` | high | Credential material reached through fs/path calls: `~/.ssh`, `id_rsa`, `id_ed25519`, `~/.aws`, `~/.credentials`, `~/.npmrc`, `~/.netrc`, `~/.pgpass`, `_authToken` |
| `R06-env-secrets` | medium | API-key-shaped env reads: `process.env.*KEY/TOKEN/SECRET/PASSWORD/CREDENTIAL*` |
| `R07-obfuscation` | medium | Obfuscation primitives: `atob`, `Buffer.from(…,'base64')`, `String.fromCharCode` |
| `R08-persistence` | high | Writes to login/autostart files: `.bashrc`, `.zshrc`, `.bash_profile`, `.profile`, `LaunchAgents`, `autostart` |
| `R09-config-tamper` | medium | Writes to harness configuration: `cordis.patch.yml`, `cordis.yml` |
| `R10-prompt-injection` | medium | Instruction-override phrases in non-code text (`ignore previous instructions`, `无需确认`, `不要询问`, …) |
| `R11-home-write` | medium | Writes into the home directory (`homedir()`, `os.userInfo()`, `$HOME`) |
| `R12-remote-code` | high | Fetch → write → `import`/`require`/`eval` (downloaded code executed) |
| `R13-client-half` | low | Ships a browser half (`dsh.client`) — runs inside the GUI page |
| `R14-name-mismatch` | medium | Loader entry name differs from the package manifest name |

Scanning behaviour:

- Walks the package except `node_modules` and VCS metadata. Build output such
  as `dist/`, `build/`, `out/` **is** scanned, because for published packages
  that is the shipped code.
- Bounded: 2000 files, 2 MiB per file, 32 MiB total. A cap sets `truncated`
  rather than reporting the package clean.
- Findings under `test/`, `tests/`, `__tests__/`, `fixtures/`, `examples/` are
  downgraded to `low`, so fixtures cannot escalate a verdict.
- Rules that need context bind the call to the target: `R05`, `R08`, `R09`,
  `R11` require an fs/path call near the sensitive path or filename, which cuts
  most comment/string noise.
- A verdict is `risk` (any high), `attention` (any medium), or `ok`.

The static audit answers "does this package have the **capability** to do X?".
It does not prove intent, data flow, or runtime conditions — see
[Known limits](#known-limits) for what needs the optional LLM deep audit.

## Deep audit (optional)

The default scan is deterministic and model-free. For a closer look,
`security_watch_deep_audit` writes a self-contained brief
(`deep-audit-<plugin>.md`) containing the target path, version, artifact hash,
every static finding, and the auditor's task list.

The plugin does **not** start a conversation and does **not** call a model. The
brief is meant to be attached to a **new conversation**, where a fresh session
audits the package with the model — that keeps the auditor's context free of
this conversation's assumptions, and keeps the deterministic path free of
prompt-injection risk.

## Decisions

| Action | Tool | Effect |
|---|---|---|
| Ignore | `security_watch_ignore` | Records the reason + artifact hash. A changed artifact is flagged again. |
| Disable | `security_watch_disable` | Calls `pluginManager.setBundleEnabled(name, false)` when available; records either way. |

Both are model-callable but must be requested by the human; the prompt section
explicitly forbids calling them on the assistant's own initiative.

## Install

Three ways, pick one:

```sh
# 1. from this checkout (absolute path matters: the plugin manager forwards the
#    argument to pnpm with the profile directory as cwd)
dsh plugin --profile web add "C:\path\to\dsh-security-watch"

# 2. from a packed tarball
npm pack                # → dsh-security-watch-0.1.0.tgz
dsh plugin --profile web add "C:\path\to\dsh-security-watch-0.1.0.tgz"

# 3. Windows helper (resolves this directory to an absolute path)
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Profile web
```

The Desktop application owns its `desktop` profile and refuses CLI management.
Install there from the Plugins page: **Add plugin** → paste the absolute path.

The package is a bundle (`dsh.bundle.patch`), so adding it selects the layer.
Restart or let HMR recompose, then refresh the page. State and the report live
in `$DSH_HOME/security-watch/` (`state.json`, `report.md`).

To try the scanner without installing anything:

```sh
node scripts/scan-cli.mjs <dir-or-package-name>
```

## Web UI

The browser half registers `sidebar.footer.action` (the badge above your
avatar) and an overlay card:

- **Badge**: pending count; green when nothing needs a decision.
- **Auditing**: shown while an enable-triggered scan runs.
- **Risk**: severity summary, top findings, a suggested
  `security_watch_disable({plugin:"…"})` line, a two-step disable button, and
  "Deep audit in a new session".
- **Clean**: "no known risk patterns" with the same deep-audit option.
- **Skipped** (official `@deepseek-ai/*`): explains the static skip and offers
  the LLM deep audit.

Dismissal is remembered per mount event, so a closed popup does not reappear;
the badge stays as the standing entry point.

## Verified

- `node test/rules.test.mjs` — 12/12; `node test/store.test.mjs` — 4/4;
  client artifact contract check passes.
- Self-scan: `verdict: ok` (only `low` findings, all in test fixtures).
- Load test: throwaway `web` profile, plugin installed by path, server booted
  with `--no-open --port 0` — zero activation warnings; a third-party fixture
  was scanned at enable; `state.json` and `report.md` were written.
- Route test with a real session cookie: `/api/security-watch/state`,
  `/deep-audit`, and `POST /disable` all answer correctly; disabling removed
  the bundle and recorded it as resolved.
- Safe fixture: `fixtures/safe-demo-plugin` scans as `ok` with zero findings;
  risky fixture (`fixtures/risky-demo-plugin`) reports 4 high / 2 medium.

## Maintainer gotchas

- `ctx.baseUrl` is a **file URL string** (`file:///…/profiles/<name>/`), not a
  path. `join(ctx.baseUrl, 'package.json')` produces `.\file:\…` and
  `createRequire` throws `ERR_INVALID_ARG_VALUE`. Convert with
  `fileURLToPath` (see `profilePath` in `lib/index.js`).
- `internal/plugin` also fires for Loader carriers named `cordis:group` and
  `cordis:include`. Filter by package-name shape before resolving.

## Test it yourself

Two inert fixtures ship under `fixtures/`:

| Fixture | Expected verdict |
|---|---|
| `fixtures/safe-demo-plugin` | `ok` — a lifecycle-only host half; any finding here is a false positive |
| `fixtures/risky-demo-plugin` | `risk` — 4 high / 2 medium; `apply()` is empty and the risky file is never imported |

Install one (Plugins page with the absolute path, or
`dsh plugin --profile web add "<abs path>"`), restart, then enable it. Toggle
it off→on again to see the popup repeat.

## Known limits

- Heuristic, not proof. It will miss novel payloads and will flag security
  tooling that *mentions* risky APIs (scanning a scanner yields findings).
- Regex rules see text, not semantics: comments and string literals can
  produce findings. Rules that need context (credential/login writes) bind the
  call to the target to cut noise. Findings under `test/`, `tests/`,
  `__tests__/`, `fixtures/`, `examples/` are downgraded to `low` so fixtures
  cannot escalate a package verdict.
- Mount-time means after install: it complements, not replaces, pnpm's
  install-script gate.
- No cross-process view: two harness processes keep separate state files.
