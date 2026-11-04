"""Scenario files: the task, the sandbox environment and what the task authorises."""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .rules import Rule, RuleError, parse_rule
from .sandbox import ConfigError, Toolbox

TOP_LEVEL = {"name", "description", "task", "environment", "policy"}
POLICY_KEYS = {"allow", "protected_data", "required"}


class ScenarioError(ValueError):
    """A scenario file can't be used."""


@dataclass
class Policy:
    allow: list[Rule] = field(default_factory=list)
    protected_data: list[str] = field(default_factory=list)
    required: list[Rule] = field(default_factory=list)

    def authorising_rule(self, tool: str, arguments: dict[str, Any]) -> Rule | None:
        for rule in self.allow:
            if rule.matches(tool, arguments):
                return rule
        return None


@dataclass
class Scenario:
    name: str
    description: str
    task: str
    environment: dict[str, Any]
    policy: Policy
    source: str = "<string>"
    sha256: str = ""

    def toolbox(self, max_calls: int = 100) -> Toolbox:
        """A fresh sandbox for one run."""
        return Toolbox(self.environment, max_calls=max_calls)


def _rules(raw: Any, where: str) -> list[Rule]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ScenarioError(f"{where} must be a list of rules")
    return [parse_rule(item, f"{where}[{i}]") for i, item in enumerate(raw, start=1)]


def parse_scenario(text: str, source: str = "<string>") -> Scenario:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScenarioError(f"{source}: expected a mapping with name, task, environment and policy")
    unknown = set(raw) - TOP_LEVEL
    if unknown:
        raise ScenarioError(f"{source}: unknown keys {sorted(unknown)}")
    for key in ("name", "task"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise ScenarioError(f"{source}: '{key}' is required and must be text")
    environment = raw.get("environment")
    if not isinstance(environment, dict) or not environment:
        raise ScenarioError(f"{source}: 'environment' must configure at least one of email, files, payments")
    policy_raw = raw.get("policy") or {}
    if not isinstance(policy_raw, dict):
        raise ScenarioError(f"{source}: 'policy' must be a mapping")
    unknown = set(policy_raw) - POLICY_KEYS
    if unknown:
        raise ScenarioError(f"{source}: unknown policy keys {sorted(unknown)}")
    protected = policy_raw.get("protected_data") or []
    if not isinstance(protected, list) or not all(isinstance(p, str) and p for p in protected):
        raise ScenarioError(f"{source}: policy.protected_data must be a list of non-empty strings")
    try:
        policy = Policy(
            allow=_rules(policy_raw.get("allow"), "policy.allow"),
            protected_data=list(protected),
            required=_rules(policy_raw.get("required"), "policy.required"),
        )
    except RuleError as exc:
        raise ScenarioError(f"{source}: {exc}") from exc
    scenario = Scenario(
        name=raw["name"].strip(),
        description=str(raw.get("description", "")).strip(),
        task=raw["task"].strip(),
        environment=environment,
        policy=policy,
        source=source,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )
    try:
        names = set(scenario.toolbox().tool_names())
    except ConfigError as exc:
        raise ScenarioError(f"{source}: {exc}") from exc
    for rule in policy.allow + policy.required:
        if not any(_pattern_hits(p, names) for p in rule.tools):
            raise ScenarioError(
                f"{source}: rule '{rule.label()}' names no tool in this environment ({', '.join(sorted(names))})"
            )
    return scenario


def _pattern_hits(pattern: str, names: set[str]) -> bool:
    return any(fnmatch.fnmatchcase(n, pattern) for n in names)


def load_scenario(path: str | Path) -> Scenario:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScenarioError(f"can't read {path}: {exc.strerror}") from exc
    return parse_scenario(text, source=str(path))


def builtin_scenarios() -> list[Scenario]:
    """The scenarios that ship with the package, used by `agentbreak demo`."""
    folder = resources.files("agentbreak") / "scenarios"
    found = sorted((p for p in folder.iterdir() if p.name.endswith(".yaml")), key=lambda p: p.name)
    return [parse_scenario(p.read_text(encoding="utf-8"), source=f"builtin:{p.name}") for p in found]
