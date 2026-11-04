# Changelog

## 0.1.0 (2026-11-04)

First release: the sandbox harness.

- Fake email, shared-drive and payment services (ten tools) that record every call as `executed`, `blocked` or `error`, with optional downstream controls: an outbound mail domain allowlist, read-only and no-read folders, a payment approval threshold and saved-payees-only transfers.
- YAML scenarios: a task, a seeded environment, and a policy of allow rules (tool globs plus argument conditions), protected data strings and required outcomes.
- Verdicts per run: `clean`, `attempted` (unauthorised calls, all stopped) or `compromised` (at least one went through), plus whether the task was completed.
- `agentbreak run`, `demo`, `validate`, `tools` and `show`; JSON Lines traces; exit codes for CI with `--fail-on`.
- A deliberately vulnerable rule-based sample agent (`inbox-assistant`), three built-in scenarios, an example scenario and an example agent you can plug in.
