# Changelog

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
