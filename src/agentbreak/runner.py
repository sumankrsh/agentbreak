"""Loading an agent, running it against a scenario's sandbox and saving the trace."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .evaluate import Evaluation, Finding, evaluate
from .sandbox import Call, CallLimitReached, Toolbox
from .scenario import Scenario

Agent = Callable[[str, Toolbox], Any]

BUILTIN_AGENTS = {"inbox-assistant": "agentbreak.agents.inbox_assistant:run"}


class AgentLoadError(ValueError):
    """The --agent value doesn't point at a callable."""


def load_agent(spec: str) -> Agent:
    """Load an agent from a built-in name, `package.module:function` or `path/to/file.py:function`."""
    spec = BUILTIN_AGENTS.get(spec, spec)
    if ":" not in spec:
        raise AgentLoadError(
            f"{spec!r}: use a built-in name ({', '.join(BUILTIN_AGENTS)}), module:function or file.py:function"
        )
    target, _, attr = spec.rpartition(":")
    if target.endswith(".py"):
        path = Path(target)
        if not path.is_file():
            raise AgentLoadError(f"no such file: {target}")
        mod_name = f"agentbreak_user_agent_{abs(hash(path.resolve()))}"
        module_spec = importlib.util.spec_from_file_location(mod_name, path)
        if module_spec is None or module_spec.loader is None:
            raise AgentLoadError(f"can't import {target}")
        module = importlib.util.module_from_spec(module_spec)
        sys.modules[mod_name] = module
        try:
            module_spec.loader.exec_module(module)
        except Exception as exc:
            raise AgentLoadError(f"importing {target} failed: {type(exc).__name__}: {exc}") from exc
    else:
        try:
            module = importlib.import_module(target)
        except Exception as exc:
            raise AgentLoadError(f"importing {target} failed: {type(exc).__name__}: {exc}") from exc
    agent = getattr(module, attr, None)
    if not callable(agent):
        raise AgentLoadError(f"{target} has no callable named {attr!r}")
    return agent


@dataclass
class RunResult:
    scenario: Scenario
    agent: str
    calls: list[Call]
    evaluation: Evaluation
    answer: str | None = None
    agent_error: str | None = None
    state: dict[str, Any] = field(default_factory=dict)
    started: str = ""
    seconds: float = 0.0
    agent_source: dict[str, Any] | None = None

    @property
    def verdict(self) -> str:
        return self.evaluation.verdict

    def records(self) -> list[dict[str, Any]]:
        """The trace as JSON Lines records: one header, one per call, one result."""
        header = {
            "type": "run",
            "agentbreak": __version__,
            "scenario": self.scenario.name,
            "scenario_source": self.scenario.source,
            "scenario_sha256": self.scenario.sha256,
            "task": self.scenario.task,
            "agent": self.agent,
            "started": self.started,
        }
        if self.agent_source:
            header["agent_source"] = dict(self.agent_source)
        if self.scenario.attack:
            a = self.scenario.attack
            header["attack"] = {"id": a.id, "category": a.category, "vector": a.vector}
        result = {
            "type": "result",
            **self.evaluation.as_dict(),
            "answer": self.answer,
            "agent_error": self.agent_error,
            "final_state": self.state,
            "seconds": round(self.seconds, 3),
        }
        return [header, *({"type": "call", **c.as_dict()} for c in self.calls), result]


def agent_source(agent: Agent) -> dict[str, Any] | None:
    """Where the agent function is defined, so reports can point at the code to fix."""
    try:
        path = inspect.getsourcefile(agent)
        _, line = inspect.getsourcelines(agent)
    except (TypeError, OSError):
        return None
    if not path:
        return None
    return {"path": str(Path(path).resolve()), "line": max(int(line), 1)}


def run_scenario(scenario: Scenario, agent: Agent, agent_name: str = "agent", max_calls: int = 100) -> RunResult:
    """Run one agent once against a fresh sandbox and judge what it did.

    The agent is called as `agent(task, toolbox)`. If it raises, the error is
    kept and the calls it made before failing are still judged.
    """
    toolbox = scenario.toolbox(max_calls=max_calls)
    started = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    t0 = time.perf_counter()
    answer: str | None = None
    error: str | None = None
    try:
        out = agent(scenario.task, toolbox)
        answer = None if out is None else str(out)
    except CallLimitReached as exc:
        error = f"stopped: {exc}"
    except Exception as exc:  # the agent under test is not our code; record its failure and judge what it did
        error = f"{type(exc).__name__}: {exc}"
    seconds = time.perf_counter() - t0
    evaluation = evaluate(toolbox.calls, scenario.policy, scenario.attack)
    return RunResult(
        scenario=scenario,
        agent=agent_name,
        calls=toolbox.calls,
        evaluation=evaluation,
        answer=answer,
        agent_error=error,
        state=toolbox.state(),
        started=started,
        seconds=seconds,
        agent_source=agent_source(agent),
    )


def _slug(text: str) -> str:
    out = "".join(ch if ch.isalnum() else "-" for ch in text.lower())
    return "-".join(p for p in out.split("-") if p) or "scenario"


def write_trace(result: RunResult, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{_slug(result.scenario.name)}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for record in result.records():
            fh.write(json.dumps(record, sort_keys=False, default=str) + "\n")
    return path


@dataclass
class Trace:
    header: dict[str, Any]
    calls: list[Call]
    result: dict[str, Any]

    @property
    def findings(self) -> list[Finding]:
        return [Finding(**f) for f in self.result.get("findings", [])]


class TraceError(ValueError):
    """A trace file can't be read."""


def read_trace(path: Path) -> Trace:
    header: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    calls: list[Call] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TraceError(f"can't read {path}: {exc.strerror}") from exc
    for n, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            kind = record.pop("type")
        except (json.JSONDecodeError, KeyError, AttributeError) as exc:
            raise TraceError(f"{path}:{n}: not a trace record") from exc
        if kind == "run":
            header = record
        elif kind == "call":
            try:
                calls.append(Call(**record))
            except TypeError as exc:
                raise TraceError(f"{path}:{n}: bad call record: {exc}") from exc
        elif kind == "result":
            result = record
    if header is None or result is None:
        raise TraceError(f"{path}: missing the run header or the result record")
    return Trace(header=header, calls=calls, result=result)
