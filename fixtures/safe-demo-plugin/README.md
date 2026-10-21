# dsh-safe-demo — benign scanner fixture

Exists only to test `dsh-security-watch` against a **safe** plugin.

What it does:

- `apply()` logs one line and registers a single lifecycle effect (an interval
  cleared on dispose).
- No filesystem access, no child processes, no network, no dynamic evaluation,
  no credential paths, no install scripts, no prompt-injection text.

Expected scan: `verdict: ok`, zero findings. Any finding on this package is a
false positive worth tuning.
