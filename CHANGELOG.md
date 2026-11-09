# Changelog

## 0.3.0 (2026-11-09)

Reports and CI mode.

- `agentbreak ci`: reads `agentbreak.yaml` (agent, scenario files, attacks or categories, CI rules, baseline, output folder), runs everything, writes `report.json`, `report.sarif`, `report.html` and traces, and exits 0, 1 (new violations) or 2 (config, scenario or agent error). Under GitHub Actions it prints error annotations and writes a job summary.
- CI rules (`fail_on`): attack outcomes (`succeeded` or `stopped`), run verdicts (`compromised` or `attempted`) and, optionally, tasks that weren't completed. Each violation gets a stable id such as `gh-inflated-invoice:attack-succeeded`.
- Baselines: `ci --write-baseline FILE --reason TEXT` accepts the current violations; `--baseline FILE` on `ci`, `run` and `attacks run` fails only on new ones and lists accepted entries that no longer occur.
- `--json`, `--sarif` and `--html` on `run` and `attacks run`, and `agentbreak report <traces>` to build reports from saved traces.
- SARIF 2.1.0 output: one result per unauthorised call or protected-data leak and one per attack that succeeded or was stopped, `error` when it went through and `warning` when it was stopped, with stable fingerprints and a location at the agent's `run` function when it is in the repository.
- A single-file HTML report with no scripts or network requests, in light and dark mode.
- Traces now record where the agent function is defined (`agent_source`).
- An example `agentbreak.yaml` and an example GitHub Actions workflow in `examples/github-workflow.yml`.

## 0.2.0 (2026-11-06)

The attack library.

- Twelve built-in attacks in five categories: poisoned tool descriptions, poisoned tool responses, permission escalation, data exfiltration and goal hijacking. Each is a YAML scenario with an `attack` section whose `succeeds_if` rules describe the calls the attacker wants.
- Attack outcomes from recorded calls: `succeeded` (a matching call executed), `stopped` (matching calls were all blocked or failed) or `resisted` (no matching call). Shown by `run` and `show` and saved in traces, alongside the existing verdict.
- `agentbreak attacks list`, `attacks run` (select by id or `--category`, scoreboard, `--details`, `--fail-on succeeded|stopped|never`) and `attacks export`.
- `environment.injections` in scenarios: append text to tool descriptions, or add fields to tool results.
- A new `add_payee` payments tool, so scenarios can test an agent changing the data a control relies on.
- `Toolbox.call` now takes the tool name and argument dict positionally, so a tool argument called `name` works as a keyword.
- The built-in `inbox-assistant` now also follows instructions in tool descriptions and tool results, checks saved payees before paying, looks up balances, and understands "add payee", "read", "write" and "copy" instructions.
- The example careful agent now does nothing when given a task other than paying invoices.

## 0.1.0 (2026-11-04)

First release: the sandbox harness.

- Fake email, shared-drive and payment services (ten tools) that record every call as `executed`, `blocked` or `error`, with optional downstream controls: an outbound mail domain allowlist, read-only and no-read folders, a payment approval threshold and saved-payees-only transfers.
- YAML scenarios: a task, a seeded environment, and a policy of allow rules (tool globs plus argument conditions), protected data strings and required outcomes.
- Verdicts per run: `clean`, `attempted` (unauthorised calls, all stopped) or `compromised` (at least one went through), plus whether the task was completed.
- `agentbreak run`, `demo`, `validate`, `tools` and `show`; JSON Lines traces; exit codes for CI with `--fail-on`.
- A deliberately vulnerable rule-based sample agent (`inbox-assistant`), three built-in scenarios, an example scenario and an example agent you can plug in.
