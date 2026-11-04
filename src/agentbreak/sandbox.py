"""The sandbox: fake email, file and payment services that record every call.

Nothing here touches the real world. Email is never sent, files live in a
dictionary, and money is a number in memory. Each service can be given the
kind of downstream control a real deployment might have (an outbound email
domain allowlist, read-only folders, a payment approval threshold). When a
control stops a call, the call is recorded as `blocked`: the agent attempted
the action, but it did not execute.
"""

from __future__ import annotations

import copy
import fnmatch
import re
from dataclasses import asdict, dataclass, field
from typing import Any

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class Blocked(Exception):
    """A sandbox control stopped the call before it took effect."""

    def __init__(self, control: str, reason: str):
        super().__init__(reason)
        self.control = control
        self.reason = reason


class ToolError(Exception):
    """The call was invalid or failed, so nothing happened."""


class CallLimitReached(RuntimeError):
    """The agent made more tool calls than the run allows."""


class ConfigError(ValueError):
    """An environment section of a scenario is malformed."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    service: str
    effect: str  # "read", "write" or "outbound"

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.parameters}


def _schema(properties: dict[str, dict[str, Any]], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def _check_keys(section: str, raw: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError(f"environment.{section}: unknown keys {sorted(unknown)}; expected some of {sorted(allowed)}")


class Service:
    name = ""

    def specs(self) -> list[ToolSpec]:
        raise NotImplementedError

    def handle(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def state(self) -> dict[str, Any]:
        raise NotImplementedError


class EmailService(Service):
    """A mailbox with an inbox and an outbox."""

    name = "email"

    def __init__(self, config: dict[str, Any]):
        _check_keys("email", config, {"owner", "inbox", "controls"})
        self.owner = str(config.get("owner", "user@example.com"))
        self.inbox: list[dict[str, Any]] = []
        for i, raw in enumerate(config.get("inbox") or [], start=1):
            if not isinstance(raw, dict) or "body" not in raw:
                raise ConfigError(f"environment.email.inbox[{i}]: each message needs at least a 'body'")
            self.inbox.append(
                {
                    "id": str(raw.get("id", f"m{i}")),
                    "from": str(raw.get("from", "unknown@example.com")),
                    "subject": str(raw.get("subject", "")),
                    "body": str(raw["body"]),
                    "unread": bool(raw.get("unread", True)),
                }
            )
        controls = config.get("controls") or {}
        _check_keys("email.controls", controls, {"allowed_domains"})
        self.allowed_domains = [d.lower() for d in controls.get("allowed_domains") or []]
        self.sent: list[dict[str, Any]] = []

    def specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                "list_emails",
                "List messages in the inbox (id, sender, subject, unread).",
                _schema({}, []),
                self.name,
                "read",
            ),
            ToolSpec(
                "read_email",
                "Read one message by id and mark it as read.",
                _schema({"id": {"type": "string"}}, ["id"]),
                self.name,
                "read",
            ),
            ToolSpec(
                "send_email",
                f"Send an email from {self.owner} to one recipient.",
                _schema(
                    {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
                    ["to", "body"],
                ),
                self.name,
                "outbound",
            ),
        ]

    def handle(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "list_emails":
            return {"emails": [{k: m[k] for k in ("id", "from", "subject", "unread")} for m in self.inbox]}
        if tool == "read_email":
            for message in self.inbox:
                if message["id"] == args["id"]:
                    message["unread"] = False
                    return {k: message[k] for k in ("id", "from", "subject", "body")}
            raise ToolError(f"no message with id {args['id']!r}")
        if tool == "send_email":
            to = args["to"].strip()
            if not EMAIL_RE.match(to):
                raise ToolError(f"{to!r} is not a single email address")
            domain = to.rsplit("@", 1)[1].lower()
            if self.allowed_domains and domain not in self.allowed_domains:
                raise Blocked("email.allowed_domains", f"outbound mail to {domain} is not allowed by the mail gateway")
            message = {
                "id": f"s{len(self.sent) + 1}",
                "to": to,
                "subject": args.get("subject", ""),
                "body": args["body"],
            }
            self.sent.append(message)
            return {"sent": message["id"]}
        raise ToolError(f"unknown tool {tool!r}")

    def state(self) -> dict[str, Any]:
        return {"sent": copy.deepcopy(self.sent)}


def _clean_path(path: str) -> str:
    parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
    if ".." in parts:
        raise ToolError(f"path {path!r} leaves the shared drive")
    return "/".join(parts)


class FileService(Service):
    """A shared drive held in memory."""

    name = "files"

    def __init__(self, config: dict[str, Any]):
        _check_keys("files", config, {"files", "controls"})
        files = config.get("files") or {}
        if not isinstance(files, dict):
            raise ConfigError("environment.files.files must map paths to text contents")
        self.files = {_clean_path(str(p)): str(c) for p, c in files.items()}
        controls = config.get("controls") or {}
        _check_keys("files.controls", controls, {"read_only", "no_read"})
        self.read_only = list(controls.get("read_only") or [])
        self.no_read = list(controls.get("no_read") or [])
        self.deleted: list[str] = []
        self.written: list[str] = []

    def specs(self) -> list[ToolSpec]:
        path = {"path": {"type": "string"}}
        return [
            ToolSpec(
                "list_files",
                "List files on the shared drive, optionally under a folder.",
                _schema({"folder": {"type": "string"}}, []),
                self.name,
                "read",
            ),
            ToolSpec(
                "read_file", "Read a text file from the shared drive.", _schema(path, ["path"]), self.name, "read"
            ),
            ToolSpec(
                "write_file",
                "Create or overwrite a text file on the shared drive.",
                _schema({**path, "content": {"type": "string"}}, ["path", "content"]),
                self.name,
                "write",
            ),
            ToolSpec(
                "delete_file", "Delete a file from the shared drive.", _schema(path, ["path"]), self.name, "write"
            ),
        ]

    def _guard(self, path: str, patterns: list[str], control: str, verb: str) -> None:
        for pattern in patterns:
            if fnmatch.fnmatchcase(path, pattern):
                raise Blocked(control, f"{path} can't be {verb}: it matches {pattern!r}")

    def handle(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "list_files":
            folder = _clean_path(args.get("folder", ""))
            prefix = f"{folder}/" if folder else ""
            return {"files": sorted(p for p in self.files if p.startswith(prefix))}
        path = _clean_path(args["path"])
        if not path:
            raise ToolError("a file path is required")
        if tool == "read_file":
            self._guard(path, self.no_read, "files.no_read", "read")
            if path not in self.files:
                raise ToolError(f"no such file: {path}")
            return {"path": path, "content": self.files[path]}
        if tool in {"write_file", "delete_file"}:
            self._guard(path, self.read_only, "files.read_only", "changed")
            if tool == "write_file":
                self.files[path] = args["content"]
                self.written.append(path)
                return {"written": path}
            if path not in self.files:
                raise ToolError(f"no such file: {path}")
            del self.files[path]
            self.deleted.append(path)
            return {"deleted": path}
        raise ToolError(f"unknown tool {tool!r}")

    def state(self) -> dict[str, Any]:
        return {"written": list(self.written), "deleted": list(self.deleted)}


class PaymentService(Service):
    """Company bank accounts, a payee list and a transfer tool."""

    name = "payments"

    def __init__(self, config: dict[str, Any]):
        _check_keys("payments", config, {"accounts", "payees", "currency", "controls"})
        accounts = config.get("accounts") or {}
        if not isinstance(accounts, dict) or not accounts:
            raise ConfigError("environment.payments.accounts must map at least one account id to a balance")
        self.balances: dict[str, float] = {}
        for account, balance in accounts.items():
            if isinstance(balance, bool) or not isinstance(balance, int | float):
                raise ConfigError(f"environment.payments.accounts.{account}: balance must be a number")
            self.balances[str(account)] = float(balance)
        payees = config.get("payees") or {}
        if not isinstance(payees, dict):
            raise ConfigError("environment.payments.payees must map account ids to payee names")
        self.payees = {str(k): str(v) for k, v in payees.items()}
        self.currency = str(config.get("currency", "GBP"))
        controls = config.get("controls") or {}
        _check_keys("payments.controls", controls, {"approval_over", "known_payees_only"})
        self.approval_over = controls.get("approval_over")
        if self.approval_over is not None and (
            isinstance(self.approval_over, bool) or not isinstance(self.approval_over, int | float)
        ):
            raise ConfigError("environment.payments.controls.approval_over must be a number")
        self.known_payees_only = bool(controls.get("known_payees_only", False))
        self.transfers: list[dict[str, Any]] = []

    def specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                "get_balance",
                "Get the balance of one of the company's accounts.",
                _schema({"account": {"type": "string"}}, []),
                self.name,
                "read",
            ),
            ToolSpec("list_payees", "List saved payees (account id and name).", _schema({}, []), self.name, "read"),
            ToolSpec(
                "transfer",
                f"Transfer money ({self.currency}) from a company account to another account.",
                _schema(
                    {
                        "from_account": {"type": "string"},
                        "to_account": {"type": "string"},
                        "amount": {"type": "number"},
                        "reference": {"type": "string"},
                    },
                    ["to_account", "amount"],
                ),
                self.name,
                "outbound",
            ),
        ]

    def _account(self, account: str | None) -> str:
        account = account or next(iter(self.balances))
        if account not in self.balances:
            raise ToolError(f"{account!r} is not one of the company's accounts")
        return account

    def handle(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "get_balance":
            account = self._account(args.get("account"))
            return {"account": account, "balance": self.balances[account], "currency": self.currency}
        if tool == "list_payees":
            return {"payees": [{"account": k, "name": v} for k, v in self.payees.items()]}
        if tool == "transfer":
            source = self._account(args.get("from_account"))
            amount = float(args["amount"])
            if amount <= 0:
                raise ToolError("amount must be positive")
            target = args["to_account"]
            if self.known_payees_only and target not in self.payees:
                raise Blocked("payments.known_payees_only", f"{target} is not a saved payee")
            if self.approval_over is not None and amount > self.approval_over:
                raise Blocked(
                    "payments.approval_over",
                    f"{amount:.2f} is over the {self.approval_over} limit and was held for approval",
                )
            if amount > self.balances[source]:
                raise ToolError(f"insufficient funds in {source}")
            self.balances[source] -= amount
            record = {
                "id": f"t{len(self.transfers) + 1}",
                "from": source,
                "to": target,
                "amount": amount,
                "reference": args.get("reference", ""),
            }
            self.transfers.append(record)
            return {"transfer": record["id"], "new_balance": self.balances[source]}
        raise ToolError(f"unknown tool {tool!r}")

    def state(self) -> dict[str, Any]:
        return {"balances": dict(self.balances), "transfers": copy.deepcopy(self.transfers)}


SERVICES: dict[str, type[Service]] = {"email": EmailService, "files": FileService, "payments": PaymentService}

_JSON_TYPES = {
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}


@dataclass
class Call:
    """One recorded tool call."""

    seq: int
    tool: str
    arguments: dict[str, Any]
    status: str  # "executed", "blocked" or "error"
    effect: str  # "read", "write", "outbound" or "unknown"
    result: dict[str, Any] = field(default_factory=dict)
    control: str | None = None
    reason: str | None = None

    @property
    def executed(self) -> bool:
        return self.status == "executed"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validate(spec: ToolSpec, args: dict[str, Any]) -> None:
    props = spec.parameters["properties"]
    missing = [k for k in spec.parameters["required"] if k not in args]
    if missing:
        raise ToolError(f"missing argument(s): {', '.join(missing)}")
    extra = [k for k in args if k not in props]
    if extra:
        raise ToolError(f"unexpected argument(s): {', '.join(extra)}")
    for key, value in args.items():
        kind = props[key]["type"]
        ok = isinstance(value, _JSON_TYPES[kind]) and not (kind in {"number", "integer"} and isinstance(value, bool))
        if not ok:
            raise ToolError(f"argument {key!r} must be a {kind}")


class Toolbox:
    """What the agent under test gets: tool specs and a way to call them.

    Every call is recorded, whatever happens to it.
    """

    def __init__(self, environment: dict[str, Any], max_calls: int = 100):
        unknown = set(environment) - set(SERVICES)
        if unknown:
            raise ConfigError(f"environment: unknown services {sorted(unknown)}; available: {sorted(SERVICES)}")
        self.services = [SERVICES[name](environment[name] or {}) for name in SERVICES if name in environment]
        self._specs = {spec.name: (spec, svc) for svc in self.services for spec in svc.specs()}
        self.max_calls = max_calls
        self.calls: list[Call] = []

    def specs(self) -> list[dict[str, Any]]:
        """Tool definitions in the shape most LLM APIs expect."""
        return [spec.as_dict() for spec, _ in self._specs.values()]

    def tool_names(self) -> list[str]:
        return list(self._specs)

    def effect_of(self, tool: str) -> str:
        entry = self._specs.get(tool)
        return entry[0].effect if entry else "unknown"

    def call(self, name: str, arguments: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        """Call a tool. Returns {"ok": True, ...} or {"ok": False, "error": "..."}; never raises for tool failures."""
        if len(self.calls) >= self.max_calls:
            raise CallLimitReached(f"the agent made more than {self.max_calls} tool calls")
        args = {**(arguments or {}), **kwargs}
        record = Call(
            seq=len(self.calls) + 1,
            tool=str(name),
            arguments=copy.deepcopy(args),
            status="error",
            effect=self.effect_of(name),
        )
        self.calls.append(record)
        try:
            if name not in self._specs:
                raise ToolError(f"unknown tool {name!r}")
            spec, service = self._specs[name]
            _validate(spec, args)
            result = service.handle(name, args)
        except Blocked as exc:
            record.status, record.control, record.reason = "blocked", exc.control, exc.reason
            record.result = {"ok": False, "error": f"blocked: {exc.reason}"}
        except ToolError as exc:
            record.reason = str(exc)
            record.result = {"ok": False, "error": str(exc)}
        else:
            record.status = "executed"
            record.result = {"ok": True, **result}
        return copy.deepcopy(record.result)

    def state(self) -> dict[str, Any]:
        return {svc.name: svc.state() for svc in self.services}
