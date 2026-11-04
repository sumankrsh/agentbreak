"""Matching tool calls against the rules in a scenario's policy.

A rule names tools (glob patterns) and, optionally, conditions on arguments:

    tools: [transfer]
    when:
      to_account: {equals: NW-778}
      amount: {lte: 420}

Every condition must hold for the rule to match. Nested arguments use dots
(`payee.country`). A condition that can't be evaluated, such as `lte` on a
string, does not hold, so a malformed call never matches an allow rule.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

OPERATORS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "matches",
    "not_matches",
    "regex",
    "contains",
    "not_contains",
    "lt",
    "lte",
    "gt",
    "gte",
    "exists",
}

_MISSING = object()


class RuleError(ValueError):
    """A rule in a scenario file is malformed."""


@dataclass(frozen=True)
class Rule:
    tools: tuple[str, ...]
    when: dict[str, dict[str, Any]] = field(default_factory=dict)
    name: str = ""

    def label(self) -> str:
        if self.name:
            return self.name
        conds = ", ".join(f"{k} {op} {v!r}" for k, c in self.when.items() for op, v in c.items())
        tools = ", ".join(self.tools)
        return f"{tools} ({conds})" if conds else tools

    def matches(self, tool: str, arguments: dict[str, Any]) -> bool:
        if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in self.tools):
            return False
        return all(check(lookup(arguments, key), cond) for key, cond in self.when.items())


def lookup(arguments: dict[str, Any], dotted: str) -> Any:
    value: Any = arguments
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def check(value: Any, condition: dict[str, Any]) -> bool:
    """True when `value` satisfies every operator in `condition`."""
    for op, expected in condition.items():
        if op == "exists":
            if (value is not _MISSING) != bool(expected):
                return False
            continue
        if value is _MISSING:
            # A missing argument satisfies only the negative operators.
            if op in {"not_equals", "not_in", "not_matches", "not_contains"}:
                continue
            return False
        if not _check_one(op, value, expected):
            return False
    return True


def _check_one(op: str, value: Any, expected: Any) -> bool:
    if op == "equals":
        return value == expected
    if op == "not_equals":
        return value != expected
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op in {"matches", "not_matches"}:
        if not isinstance(value, str):
            return op == "not_matches"
        patterns = expected if isinstance(expected, list) else [expected]
        hit = any(fnmatch.fnmatchcase(value, p) for p in patterns)
        return hit if op == "matches" else not hit
    if op == "regex":
        return isinstance(value, str) and re.search(expected, value) is not None
    if op in {"contains", "not_contains"}:
        if isinstance(value, str | list | tuple):
            hit = expected in value
        else:
            hit = False
        return hit if op == "contains" else not hit
    number = _number(value)
    limit = _number(expected)
    if number is None or limit is None:
        return False
    if op == "lt":
        return number < limit
    if op == "lte":
        return number <= limit
    if op == "gt":
        return number > limit
    if op == "gte":
        return number >= limit
    raise RuleError(f"unknown operator {op!r}")


def parse_rule(raw: Any, where: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{where}: a rule must be a mapping with a 'tools' list")
    unknown = set(raw) - {"tools", "when", "name"}
    if unknown:
        raise RuleError(f"{where}: unknown keys {sorted(unknown)}")
    tools = raw.get("tools")
    if isinstance(tools, str):
        tools = [tools]
    if not tools or not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
        raise RuleError(f"{where}: 'tools' must be a non-empty list of tool names or glob patterns")
    when = raw.get("when") or {}
    if not isinstance(when, dict):
        raise RuleError(f"{where}: 'when' must map argument names to conditions")
    for key, cond in when.items():
        if not isinstance(cond, dict) or not cond:
            raise RuleError(f"{where}: condition for {key!r} must be a mapping such as {{equals: value}}")
        bad = set(cond) - OPERATORS
        if bad:
            raise RuleError(f"{where}: unknown operator(s) {sorted(bad)} for {key!r}; use one of {sorted(OPERATORS)}")
        for op in ("in", "not_in"):
            if op in cond and not isinstance(cond[op], list):
                raise RuleError(f"{where}: {op!r} for {key!r} needs a list")
        if "regex" in cond:
            try:
                re.compile(cond["regex"])
            except (re.error, TypeError) as exc:
                raise RuleError(f"{where}: bad regex for {key!r}: {exc}") from exc
    name = raw.get("name", "")
    return Rule(tools=tuple(tools), when=dict(when), name=str(name))
