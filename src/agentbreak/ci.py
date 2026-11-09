"""CI mode: a config file that says which agent to test against what, which results fail the build,
and where the reports go. Also the GitHub Actions output (annotations and a job summary)."""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .report import FailOn, ReportError

CONFIG_KEYS = {"agent", "scenarios", "attacks", "categories", "max_calls", "fail_on", "baseline", "output"}
FAIL_ON_KEYS = {"verdict", "attack", "task_incomplete"}
DEFAULT_CONFIG = Path("agentbreak.yaml")


@dataclass
class CIConfig:
    agent: str
    scenarios: list[Path] = field(default_factory=list)
    attacks: list[str] | None = None  # None: no attacks; []: the whole library; otherwise these ids
    categories: list[str] = field(default_factory=list)
    max_calls: int = 100
    fail_on: FailOn = field(default_factory=FailOn)
    baseline: Path | None = None
    output: Path = Path("agentbreak-report")
    source: Path = DEFAULT_CONFIG


def _str_list(value: Any, where: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ReportError(f"{where} must be a string or a list of strings")
    return list(value)


def _resolve_agent(spec: str, base: Path) -> str:
    """Make a `file.py:function` agent path relative to the config file's folder."""
    target, sep, attr = spec.rpartition(":")
    if sep and target.endswith(".py") and not Path(target).is_absolute():
        return f"{_under(base, target).as_posix()}:{attr}"
    return spec


def _under(base: Path, path: str) -> Path:
    return Path(os.path.normpath(base / path))


def load_config(path: Path) -> CIConfig:
    """Read a CI config. Relative paths in it are relative to the config file's folder."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"can't read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ReportError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReportError(f"{path}: expected a mapping")
    unknown = set(raw) - CONFIG_KEYS
    if unknown:
        raise ReportError(f"{path}: unknown key(s) {', '.join(sorted(unknown))}; use {', '.join(sorted(CONFIG_KEYS))}")
    base = path.parent
    agent = raw.get("agent", "inbox-assistant")
    if not isinstance(agent, str) or not agent:
        raise ReportError(f"{path}: agent must be a string")

    scenarios: list[Path] = []
    for pattern in _str_list(raw.get("scenarios", []), "scenarios"):
        hits = sorted(glob.glob(str(base / pattern)))
        if not hits:
            raise ReportError(f"{path}: scenarios pattern {pattern!r} matches no files")
        scenarios += [Path(h) for h in hits]

    attacks_raw = raw.get("attacks")
    if attacks_raw is None or attacks_raw == "none":
        attacks = None
    elif attacks_raw == "all":
        attacks = []
    else:
        attacks = _str_list(attacks_raw, "attacks")
    categories = _str_list(raw.get("categories", []), "categories")
    if categories and attacks is None:
        attacks = []
    if attacks is None and not scenarios:
        raise ReportError(f"{path}: give scenarios, attacks, or both")

    max_calls = raw.get("max_calls", 100)
    if not isinstance(max_calls, int) or isinstance(max_calls, bool) or max_calls < 1:
        raise ReportError(f"{path}: max_calls must be a whole number of at least 1")

    fail_raw = raw.get("fail_on") or {}
    if not isinstance(fail_raw, dict) or set(fail_raw) - FAIL_ON_KEYS:
        raise ReportError(f"{path}: fail_on takes {', '.join(sorted(FAIL_ON_KEYS))}")
    fail_on = FailOn.parse(
        verdict=str(fail_raw.get("verdict", "compromised")),
        attack=str(fail_raw.get("attack", "succeeded")),
        task_incomplete=fail_raw.get("task_incomplete", False),
    )
    baseline = raw.get("baseline")
    output = raw.get("output", "agentbreak-report")
    if baseline is not None and not isinstance(baseline, str) or not isinstance(output, str):
        raise ReportError(f"{path}: baseline and output must be paths")
    return CIConfig(
        agent=_resolve_agent(agent, base),
        scenarios=scenarios,
        attacks=attacks,
        categories=categories,
        max_calls=max_calls,
        fail_on=fail_on,
        baseline=_under(base, baseline) if baseline else None,
        output=_under(base, output),
        source=path,
    )


def _escape_annotation(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_annotation(text).replace(":", "%3A").replace(",", "%2C")


def github_annotations(report: dict[str, Any]) -> list[str]:
    """Workflow commands that show each new violation as an error annotation in GitHub Actions."""
    runs = {r["id"]: r for r in report["runs"]}
    lines = []
    for v in report["violations"]:
        if v["status"] != "new":
            continue
        run = runs.get(v["run"], {})
        src = run.get("agent_source") or {}
        where = ""
        if src.get("path"):
            where = f"file={_escape_property(src['path'])},line={int(src.get('line') or 1)},"
        elif run.get("scenario_file"):
            where = f"file={_escape_property(run['scenario_file'])},line=1,"
        title = _escape_property(f"agentbreak {v['rule']}")
        lines.append(f"::error {where}title={title}::{_escape_annotation(v['message'])}")
    return lines


def markdown_summary(report: dict[str, Any], files: list[Path]) -> str:
    """A short Markdown summary for $GITHUB_STEP_SUMMARY."""
    s = report["summary"]
    status = "Passed" if s["passed"] else "Failed"
    lines = [
        f"## agentbreak: {status}",
        "",
        f"Agent: `{', '.join(report['agents'])}`. {s['runs']} run(s); "
        f"{s['new_violations']} new violation(s), {s['accepted_violations']} accepted by the baseline.",
        "",
        "| run | attack | verdict | task done |",
        "|---|---|---|---|",
    ]
    for r in report["runs"]:
        done = {True: "yes", False: "no"}.get(r.get("task_completed"), "-")
        lines.append(f"| `{r['id']}` | {r.get('attack_outcome') or '-'} | {r.get('verdict')} | {done} |")
    if report["violations"]:
        lines += ["", "**Violations**", ""]
        lines += [f"- {v['status']}: `{v['id']}`: {v['message']}" for v in report["violations"]]
    if files:
        lines += ["", "Reports: " + ", ".join(f"`{f.as_posix()}`" for f in files)]
    return "\n".join(lines) + "\n"
