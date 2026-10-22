# Changelog

## 0.1.5 — 2026-10-22

Edge cases found in a review of the scanner, store and UI. Behaviour that could
hide a problem is now explicit; nothing here changes the alarm-only contract.

- **Incomplete scans are never clean.** A scan that hit a cap, could not read a
  file, or found a symlink escaping the package is `incomplete` and at least
  `attention`. The popup, `report.md` and the badge say so.
- **The artifact hash now covers every file**, including binaries and ignored
  extensions (small binaries by content, larger ones by name+size), so swapping
  a payload invalidates a recorded ignore. Existing ignores re-flag once.
- **UTF-16 text (BOM) is decoded**, so PowerShell-style scripts are scanned by
  the text rules instead of becoming mojibake. More text extensions
  (`.bat`, `.cmd`, `.psm1`, `.toml`, `.env`, `.txt`, lock files, …) are scanned.
- **Symlinks are never followed**; links resolving outside the package are
  reported as `R15-symlink-escape`, and unreadable files as
  `R16-scan-incomplete`.
- **Depth cap (40)** so pathological trees cannot exhaust the stack.
- **State is per profile** under `$DSH_HOME/security-watch/<profile>/`; a
  pre-0.1.5 shared state is imported by the first profile that starts (marker
  file records the claim) and never re-imported by another profile. Saves are
  atomic and keep one `.bak`; a corrupt main file falls back to it.
- **New rules**: `R17-browser-credentials` (high), `R18-encoded-command`
  (medium), `R19-watcher-tamper` (medium).
- **Badge** shows a yellow `!` when a scan could not run or finish.

## 0.1.4 — 2026-10-22

- Fix "目录未找到" (unresolved) for packages that define an `exports` map
  without `./package.json`. `require.resolve('<name>/package.json')` throws
  `ERR_PACKAGE_PATH_NOT_EXPORTED` for such packages (@tencent-connect/dsh-qqbot
  exports only `.` and `./client`), so the loader entry never resolved.
  Resolution now checks the installed `node_modules` layout first and only
  falls back to Node resolution, then walks up from the entry point.
- Add `test/resolve.test.mjs` covering the exports-hidden case.

## 0.1.3 — 2026-10-22

- Fix scans stuck at "scanning" forever. A scan queued for a bundle whose
  directory was not resolvable yet (install still finishing) left the live
  entry `queued` indefinitely, and the popup only pruned finished entries.
  - Unresolvable scans are retried briefly, then settled as a skipped result.
  - A 5-minute watchdog converts any in-flight entry into a skipped result.
  - The popup now explains unresolved/watchdog skips instead of spinning.

## 0.1.2 — 2026-10-21

- Add a **Trust as false positive** action to the popup for risk/attention
  findings. It calls the new `POST /api/security-watch/ignore` route, records
  the reason and the artifact hash, and removes the item from the badge. A new
  version or a changed artifact is audited again.
- Backing route lets the Web UI record a decision without going through the
  model; the existing `security_watch_ignore` tool still works for
  conversation-driven decisions.

## 0.1.1 — 2026-10-21

Documentation only.

- Add a one-command install from the GitHub URL:
  `dsh plugin --profile web add "https://github.com/learner202649/deepseek-harness-security-watch.git#v0.1.0"`.
- Document the Desktop-app path and the `ERR_PNPM_EPERM` case caused by a
  previous `link:` install of the same package.

## 0.1.0 — 2026-10-21

Initial release.

- Host half: bounded static scan of plugin packages, alarm-only.
- Audit on enable only: startup inherits trust; an off→on transition (bundle
  diff) or a live mount after startup is audited.
- Popup and badge in the Harness Web UI, bilingual (zh/en).
- Findings: exec, dynamic exec, network, staged payload, credential paths,
  env secrets, obfuscation primitives, persistence, config tamper, prompt
  injection, home writes, remote code, install scripts, name mismatch.
- Operator actions: ignore (bound to artifact hash), disable (via the plugin
  manager), forget (drop a record), deep-audit brief for a new session.
- Official `@deepseek-ai/*` bundles are skipped by the static rules; a newly
  enabled one still shows a popup with the LLM deep-audit option.
- Disabled plugins resolve their old risk; the badge returns to green.
