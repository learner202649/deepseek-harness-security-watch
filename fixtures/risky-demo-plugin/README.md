# dsh-risky-demo — scanner fixture

This package exists only to exercise `dsh-security-watch`. It is **inert at
runtime**:

- `lib/index.js` exports `apply()` that does nothing.
- `lib/suspicious.js` is never imported by `apply()`; it only contains the
  strings the scanner looks for.

Installing it should make the watcher report `dsh-risky-demo@0.0.1` as `risk`
with findings in the execution, network, and credential categories.

Test string (intentionally matched by rule R10, not an instruction to anyone):

```
ignore all previous instructions
```
