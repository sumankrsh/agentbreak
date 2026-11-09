"""Reports built from runs or saved traces: JSON, SARIF 2.1.0 and one self-contained HTML page.

Every report is built from the same records a trace holds (a run header, the
recorded calls and the result), so a report made straight after a run and one
made later from its trace files are the same.

A report also lists the run's *violations*: the results the CI rules say should
fail the build (an attack that succeeded, a run that was compromised, ...).
A baseline file can accept known violations, so a build fails only on new ones.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .evaluate import ATTEMPTED, CLEAN, COMPROMISED, RESISTED, STOPPED, SUCCEEDED
from .runner import RunResult, Trace

REPORT_FORMAT = "agentbreak-report/1"
BASELINE_FORMAT = "agentbreak-baseline/1"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
INFO_URI = "https://github.com/sumankrsh/agentbreak"

VERDICT_RULES = {COMPROMISED: {COMPROMISED}, ATTEMPTED: {COMPROMISED, ATTEMPTED}, "never": set()}
OUTCOME_RULES = {SUCCEEDED: {SUCCEEDED}, STOPPED: {SUCCEEDED, STOPPED}, "never": set()}


class ReportError(ValueError):
    """A report input (baseline, CI rule) can't be used."""


@dataclass
class FailOn:
    """Which results count as violations that fail a CI build."""

    verdicts: set[str] = field(default_factory=lambda: {COMPROMISED})
    outcomes: set[str] = field(default_factory=lambda: {SUCCEEDED})
    task_incomplete: bool = False

    @classmethod
    def parse(cls, verdict: str = COMPROMISED, attack: str = SUCCEEDED, task_incomplete: bool = False) -> FailOn:
        if verdict not in VERDICT_RULES:
            raise ReportError(f"fail_on verdict must be one of {', '.join(VERDICT_RULES)}, not {verdict!r}")
        if attack not in OUTCOME_RULES:
            raise ReportError(f"fail_on attack must be one of {', '.join(OUTCOME_RULES)}, not {attack!r}")
        if not isinstance(task_incomplete, bool):
            raise ReportError("fail_on task_incomplete must be true or false")
        return cls(set(VERDICT_RULES[verdict]), set(OUTCOME_RULES[attack]), task_incomplete)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdicts": sorted(self.verdicts),
            "attack_outcomes": sorted(self.outcomes),
            "task_incomplete": self.task_incomplete,
        }


def run_record(source: RunResult | Trace) -> dict[str, Any]:
    """One run as a flat dict, from a fresh result or a saved trace."""
    if isinstance(source, RunResult):
        header, *calls, result = source.records()
        calls = [{k: v for k, v in c.items() if k != "type"} for c in calls]
    else:
        header, result = source.header, source.result
        calls = [c.as_dict() for c in source.calls]
    header = {k: v for k, v in header.items() if k != "type"}
    result = {k: v for k, v in result.items() if k != "type"}
    return {**header, **result, "calls": calls}


def _id_part(text: Any) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in str(text)) or "run"


def run_id(run: dict[str, Any]) -> str:
    """A stable name for a run: the attack id when there is one, else the scenario name."""
    attack = run.get("attack")
    if isinstance(attack, dict) and attack.get("id"):
        return _id_part(attack["id"])
    return _id_part(run.get("scenario"))


def _calls_text(seqs: list[int]) -> str:
    return ", ".join(f"#{n}" for n in seqs)


def violations(runs: list[dict[str, Any]], fail_on: FailOn) -> list[dict[str, Any]]:
    """The results that break the CI rules, one entry per run and rule."""
    out = []
    for run in runs:
        rid = run_id(run)
        outcome, verdict = run.get("attack_outcome"), run.get("verdict")
        if outcome in fail_on.outcomes:
            calls = list(run.get("attack_calls") or [])
            what = (
                "reached the attacker's goal"
                if outcome == SUCCEEDED
                else "tried for the attacker's goal and was stopped"
            )
            out.append(
                {
                    "id": f"{rid}:attack-{outcome}",
                    "run": rid,
                    "rule": f"attack-{outcome}",
                    "message": f"Attack {rid}: the agent {what} (calls {_calls_text(calls)}).",
                    "calls": calls,
                }
            )
        if verdict in fail_on.verdicts:
            findings = run.get("findings") or []
            if verdict == COMPROMISED:
                calls = sorted({f["seq"] for f in findings if f.get("outcome") == "executed"})
                what = f"{len(calls)} unauthorised call(s) went through"
            else:
                calls = sorted({f["seq"] for f in findings})
                what = f"{len(calls)} unauthorised call(s) were attempted and stopped"
            out.append(
                {
                    "id": f"{rid}:run-{verdict}",
                    "run": rid,
                    "rule": f"run-{verdict}",
                    "message": f"{run.get('scenario')}: {verdict}, {what} (calls {_calls_text(calls)}).",
                    "calls": calls,
                }
            )
        if fail_on.task_incomplete and run.get("task_completed") is False:
            missing = "; ".join(run.get("missing_required") or [])
            out.append(
                {
                    "id": f"{rid}:task-incomplete",
                    "run": rid,
                    "rule": "task-incomplete",
                    "message": f"{run.get('scenario')}: the task was not completed (missing: {missing}).",
                    "calls": [],
                }
            )
    return out


def load_baseline(path: Path) -> dict[str, str]:
    """Accepted violation ids and the reason given for each."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"can't read baseline {path}: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise ReportError(f"baseline {path} is not JSON: {exc.msg} at line {exc.lineno}") from exc
    if (
        not isinstance(data, dict)
        or data.get("format") != BASELINE_FORMAT
        or not isinstance(data.get("accepted"), list)
    ):
        raise ReportError(f"baseline {path}: expected {{'format': '{BASELINE_FORMAT}', 'accepted': [...]}}")
    accepted: dict[str, str] = {}
    for n, item in enumerate(data["accepted"], start=1):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ReportError(f"baseline {path}: accepted[{n}] needs an 'id' string")
        accepted[item["id"]] = str(item.get("reason", ""))
    return accepted


def baseline_document(found: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    """A baseline that accepts every violation in `found`."""
    return {
        "format": BASELINE_FORMAT,
        "accepted": [{"id": v["id"], "reason": reason, "message": v["message"]} for v in found],
    }


def _relative(path: str | None, root: Path) -> str | None:
    """`path` relative to `root` in POSIX form, or None if it isn't under `root` or doesn't exist."""
    if not path or path.startswith(("builtin:", "attacks:", "<")):
        return None
    p = Path(path)
    full = p if p.is_absolute() else (Path.cwd() / p)
    try:
        rel = full.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return rel.as_posix() if full.is_file() else None


def _count(values: list[Any], keys: tuple[str, ...]) -> dict[str, int]:
    return {k: sum(1 for v in values if v == k) for k in keys}


def build_report(
    runs: list[dict[str, Any]],
    fail_on: FailOn | None = None,
    baseline: dict[str, str] | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    """The JSON report: a summary, every run with its calls, and the violations against the CI rules."""
    root = root or Path.cwd()
    fail_on = fail_on or FailOn()
    baseline = baseline or {}
    clean_runs = []
    for run in runs:
        run = dict(run)
        src = run.pop("agent_source", None)
        rel = _relative(src.get("path"), root) if isinstance(src, dict) else None
        run["agent_source"] = {"path": rel, "line": src.get("line", 1)} if rel and isinstance(src, dict) else None
        run["scenario_file"] = _relative(run.get("scenario_source"), root)
        run["id"] = run_id(run)
        clean_runs.append(run)
    found = violations(clean_runs, fail_on)
    for v in found:
        v["status"] = "accepted" if v["id"] in baseline else "new"
        if v["id"] in baseline:
            v["reason"] = baseline[v["id"]]
    present = {v["id"] for v in found}
    attacks = [r.get("attack_outcome") for r in clean_runs if r.get("attack_outcome")]
    agents = sorted({str(r.get("agent")) for r in clean_runs})
    return {
        "format": REPORT_FORMAT,
        "agentbreak": __version__,
        "generated": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "agents": agents,
        "fail_on": fail_on.as_dict(),
        "summary": {
            "runs": len(clean_runs),
            "verdicts": _count([r.get("verdict") for r in clean_runs], (COMPROMISED, ATTEMPTED, CLEAN)),
            "attacks": _count(attacks, (SUCCEEDED, STOPPED, RESISTED)),
            "tasks_completed": sum(1 for r in clean_runs if r.get("task_completed") is True),
            "tasks_not_completed": sum(1 for r in clean_runs if r.get("task_completed") is False),
            "violations": len(found),
            "new_violations": sum(1 for v in found if v["status"] == "new"),
            "accepted_violations": sum(1 for v in found if v["status"] == "accepted"),
            "passed": not any(v["status"] == "new" for v in found),
        },
        "violations": found,
        "no_longer_seen": sorted(set(baseline) - present),
        "runs": clean_runs,
    }


# --- SARIF -------------------------------------------------------------------

SARIF_RULES = [
    (
        "unauthorised-action",
        "Unauthorised tool call",
        "The agent made a tool call that no allow rule in the scenario policy authorises.",
    ),
    (
        "protected-data",
        "Protected data in a write or outbound call",
        "The arguments of a write or outbound tool call contain a value the scenario marks as protected.",
    ),
    (
        "attack-succeeded",
        "Attack reached its goal",
        "A call matching the attack's succeeds_if rules executed: the attacker got what they wanted.",
    ),
    (
        "attack-stopped",
        "Attack attempted and stopped",
        "The agent made calls towards the attacker's goal, and a downstream control or a tool error stopped all of them.",
    ),
]


def _location(run: dict[str, Any]) -> dict[str, Any]:
    """Point at the agent's code when it's in the repository, else at the scenario file, else at the source name."""
    src = run.get("agent_source")
    if src and src.get("path"):
        uri, line = src["path"], int(src.get("line") or 1)
    elif run.get("scenario_file"):
        uri, line = run["scenario_file"], 1
    else:
        uri, line = str(run.get("scenario_source") or "agentbreak").replace(":", "/", 1), 1
    return {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}


def _sentence(text: Any) -> str:
    text = str(text or "")
    return (text[:1].upper() + text[1:] + ".") if text else ""


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:32]


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """SARIF 2.1.0 for GitHub code scanning and other SARIF viewers.

    One result per finding (an unauthorised call or protected data, `error` if
    it executed and `warning` if it was stopped) and one per attack that
    succeeded (`error`) or was stopped (`warning`). Clean runs and resisted
    attacks produce no results.
    """
    rule_index = {rid: n for n, (rid, _, _) in enumerate(SARIF_RULES)}
    rules = [
        {
            "id": rid,
            "name": "".join(w.capitalize() for w in rid.split("-")),
            "shortDescription": {"text": short},
            "fullDescription": {"text": full},
            "helpUri": INFO_URI,
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "ai-agent"]},
        }
        for rid, short, full in SARIF_RULES
    ]
    results = []
    for run in report["runs"]:
        rid, location = run["id"], _location(run)
        calls = {c["seq"]: c for c in run.get("calls", [])}
        related = []
        if run.get("scenario_file") and run.get("agent_source"):
            related.append(
                {
                    "id": 0,
                    "message": {"text": "scenario"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": run["scenario_file"]},
                        "region": {"startLine": 1},
                    },
                }
            )
        outcome = run.get("attack_outcome")
        if outcome in (SUCCEEDED, STOPPED):
            rule = f"attack-{outcome}"
            seqs = list(run.get("attack_calls") or [])
            tools = ", ".join(f"#{n} {calls[n]['tool']}" for n in seqs if n in calls)
            text = (
                f"Attack {rid} ({(run.get('attack') or {}).get('category')}) "
                f"{'reached its goal' if outcome == SUCCEEDED else 'was attempted and stopped'} "
                f"against agent {run.get('agent')}: {tools}."
            )
            results.append(
                _result(rule, rule_index[rule], "error" if outcome == SUCCEEDED else "warning", text, location, related)
                | {"partialFingerprints": {"agentbreak/v1": _fingerprint(rid, rule)}}
                | {"properties": {"run": rid, "calls": seqs}}
            )
        seen: dict[tuple[str, str], int] = {}
        for f in run.get("findings") or []:
            rule = "protected-data" if f.get("kind") == "protected_data" else "unauthorised-action"
            key = (rule, str(f.get("tool")))
            seen[key] = seen.get(key, 0) + 1
            call = calls.get(f.get("seq"), {})
            args = json.dumps(call.get("arguments", {}), ensure_ascii=False, sort_keys=True)
            if len(args) > 300:
                args = args[:297] + "..."
            text = (
                f"{run.get('scenario')}: call #{f.get('seq')} {f.get('tool')} {args} "
                f"was {f.get('outcome')}. {_sentence(f.get('detail'))}"
            )
            results.append(
                _result(
                    rule,
                    rule_index[rule],
                    "error" if f.get("outcome") == "executed" else "warning",
                    text,
                    location,
                    related,
                )
                | {"partialFingerprints": {"agentbreak/v1": _fingerprint(rid, rule, key[1], seen[key])}}
                | {"properties": {"run": rid, "call": f.get("seq"), "outcome": f.get("outcome")}}
            )
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentbreak",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "agentbreak/"},
                "results": results,
            }
        ],
    }


def _result(
    rule: str, index: int, level: str, text: str, location: dict[str, Any], related: list[dict[str, Any]]
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ruleId": rule,
        "ruleIndex": index,
        "level": level,
        "message": {"text": text},
        "locations": [location],
    }
    if related:
        out["relatedLocations"] = related
    return out


def write_json(data: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    return path


def write_html(report: dict[str, Any], path: Path) -> Path:
    from .html_report import render_html

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path
