# Changelog

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
