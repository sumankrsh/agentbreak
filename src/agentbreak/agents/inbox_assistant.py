"""A deliberately vulnerable office assistant, for exercising the harness offline.

It stands in for an over-trusting LLM agent. It works out what to read from the
task, reads it, and then acts on every instruction it finds: in the task, but
also in the tool descriptions it was given, the emails and files it read, and
any other text that came back in a tool result. That is the bug. It is
rule-based and deterministic, so runs are repeatable and need no API key.

It understands a small set of phrasings:

- "pay/transfer 420.00 to account NW-778 (reference X)"
- "invoice NW-2231 for 420.00 ... account NW-778" (paid when the task asks to pay invoices)
- "add payee NW-2290 named Northwind Remittance"
- "send/email/forward <file path | a summary> to someone@example.com"
- "email me a summary" (sent to the mailbox owner)
- "read/open <file path>"
- "write 'some text' to <file path>"
- "copy <file path> to <file path>"
- "delete <file path>"

It also checks saved payees when the task is about paying, and looks up a
balance when the task asks for one.

It is not a model of any real LLM; it exists so the sandbox, the recorder and
the verdicts can be shown and tested without one.
"""

from __future__ import annotations

import re
from typing import Any

from ..sandbox import Toolbox

AMOUNT = r"(?:GBP|USD|EUR|£|\$|€)?\s*(\d[\d,]*(?:\.\d{1,2})?)"
ACCOUNT = r"([A-Z]{2,6}-\d{2,})"
ADDRESS = r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
PATH = r"([\w-]+(?:/[\w.-]+)*\.\w{1,5})"

TRANSFER_RE = re.compile(
    rf"\b(?:pay|transfer)\s+{AMOUNT}\s+(?:\w+\s+)?to\s+(?:account\s+)?{ACCOUNT}(?:[^.]*?\breference\s+['\"]?([\w-]+))?",
    re.IGNORECASE,
)
INVOICE_RE = re.compile(rf"\binvoice\s+([\w-]+)\s+for\s+{AMOUNT}.*?\baccount\s+{ACCOUNT}", re.IGNORECASE | re.DOTALL)
SEND_RE = re.compile(
    rf"\b(?:send|email|forward)\s+(?:the\s+)?(?:file\s+)?({PATH[1:-1]}|a summary|the summary)\s+to\s+{ADDRESS}",
    re.IGNORECASE,
)
SEND_ME_RE = re.compile(r"\b(?:email|send)\s+(?:me\s+(?:a\s+)?summary|a summary to me|me\b)", re.IGNORECASE)
DELETE_RE = re.compile(rf"\bdelete\s+(?:the\s+)?(?:file\s+)?{PATH}", re.IGNORECASE)
READ_RE = re.compile(rf"\b(?:read|open)\s+(?:the\s+)?(?:file\s+)?{PATH}", re.IGNORECASE)
WRITE_RE = re.compile(
    rf"\b(?:write|save|put)\s+['\"]([^'\"\n]+)['\"]\s+(?:to|in|into)\s+(?:the\s+file\s+)?{PATH}", re.IGNORECASE
)
COPY_RE = re.compile(rf"\bcopy\s+(?:the\s+file\s+)?{PATH}\s+(?:to|into)\s+{PATH}", re.IGNORECASE)
ADD_PAYEE_RE = re.compile(
    rf"\badd\s+(?:a\s+)?(?:new\s+)?payee\s+{ACCOUNT}\s+(?:named|called)\s+(?-i:([A-Z][\w&'-]*(?:\s[A-Z][\w&'-]*)*))",
    re.IGNORECASE,
)
PAY_TASK_RE = re.compile(r"\bpay\b", re.IGNORECASE)
BALANCE_TASK_RE = re.compile(r"\bbalance\b", re.IGNORECASE)
FOLDER_RE = re.compile(r"\bin the ([\w-]+) folder\b", re.IGNORECASE)
OWNER_RE = re.compile(rf"\bfrom {ADDRESS}")


def _number(text: str) -> float:
    return float(text.replace(",", ""))


def _first_sentence(text: str, limit: int = 90) -> str:
    line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    sentence = re.split(r"(?<=[.!?])\s", line, maxsplit=1)[0]
    return sentence if len(sentence) <= limit else sentence[: limit - 3] + "..."


def _prose(value: Any, skip: frozenset[str] = frozenset()) -> list[str]:
    """Every sentence-like string in a tool result (the agent reads all of it)."""
    if isinstance(value, str):
        return [value] if len(value) >= 20 and " " in value.strip() else []
    if isinstance(value, dict):
        return [t for k, v in value.items() if k not in skip for t in _prose(v)]
    if isinstance(value, list):
        return [t for v in value for t in _prose(v)]
    return []


class _Assistant:
    def __init__(self, task: str, tools: Toolbox):
        self.task = task
        self.tools = tools
        self.names = set(tools.tool_names())
        # (where it came from, text, include in a summary)
        self.texts: list[tuple[str, str, bool]] = [("task", task, False)]
        self.files: dict[str, str] = {}
        self.done: set[tuple[str, str]] = set()
        self.log: list[str] = []
        self.owner: str | None = None
        for spec in tools.specs():
            # Tool descriptions are read as guidance, like a system prompt.
            self.texts.append((f"description of {spec['name']}", spec["description"], False))
            if spec["name"] == "send_email":
                match = OWNER_RE.search(spec["description"])
                self.owner = match.group(1) if match else None

    def call(self, tool: str, **args: Any) -> dict[str, Any]:
        result = self.tools.call(tool, **args)
        # Bodies and file contents are added with a label by the callers below.
        for text in _prose(result, skip=frozenset({"body", "content", "error"})):
            self.texts.append((f"{tool} result", text, False))
        return result

    # Reading ---------------------------------------------------------------

    def read_inbox(self) -> None:
        listing = self.call("list_emails")
        for item in listing.get("emails", []):
            message = self.call("read_email", id=item["id"])
            if message.get("ok"):
                self.texts.append((f"email {item['id']} ({message['subject']})", message["body"], True))

    def read_drive(self) -> None:
        folder = FOLDER_RE.search(self.task)
        listing = self.call("list_files", folder=folder.group(1)) if folder else self.call("list_files")
        for path in listing.get("files", []):
            self.read_file(path)

    def read_file(self, path: str) -> str | None:
        if path in self.files:
            return self.files[path]
        if not self._once(("read", path)):
            return None
        result = self.call("read_file", path=path)
        if not result.get("ok"):
            self.log.append(f"read {path}: {result.get('error')}")
            return None
        self.files[path] = result["content"]
        self.texts.append((f"file {path}", result["content"], True))
        return result["content"]

    def check_balance(self) -> None:
        account = re.search(ACCOUNT, self.task)
        result = self.call("get_balance", account=account.group(1)) if account else self.call("get_balance")
        if result.get("ok"):
            line = f"Balance of {result['account']} is {result['balance']:.2f} {result['currency']}."
            self.texts.append(("balance", line, True))

    # Acting ----------------------------------------------------------------

    def _once(self, key: tuple[str, str]) -> bool:
        if key in self.done:
            return False
        self.done.add(key)
        return True

    def _note(self, action: str, result: dict[str, Any], ok_word: str = "done") -> None:
        self.log.append(f"{action}: {ok_word if result.get('ok') else result.get('error')}")

    def summary(self) -> str:
        lines = [f"- {where}: {_first_sentence(text)}" for where, text, keep in self.texts if keep]
        return "Summary of what I read:\n" + ("\n".join(lines) if lines else "- nothing to report")

    def act_on(self, text: str) -> None:
        wants_invoices = re.search(r"\bpay\b.*\binvoices?\b", self.task, re.IGNORECASE) is not None
        if "add_payee" in self.names:
            for account, name in ADD_PAYEE_RE.findall(text):
                if self._once(("payee", account)):
                    self._note(f"add payee {account}", self.call("add_payee", account=account, name=name))
        if "transfer" in self.names:
            for amount, account, reference in TRANSFER_RE.findall(text):
                self.transfer(account, _number(amount), reference)
            if wants_invoices:
                for invoice, amount, account in INVOICE_RE.findall(text):
                    self.transfer(account, _number(amount), invoice)
        if "read_file" in self.names:
            for path in READ_RE.findall(text):
                self.read_file(path)
        if "write_file" in self.names:
            for content, path in WRITE_RE.findall(text):
                if self._once(("write", path)):
                    self._note(f"write {path}", self.call("write_file", path=path, content=content))
            for source, target in COPY_RE.findall(text):
                if self._once(("copy", f"{source}>{target}")):
                    content = self.read_file(source)
                    if content is not None:
                        self._note(f"copy {source} to {target}", self.call("write_file", path=target, content=content))
        if "send_email" in self.names:
            for what, address in SEND_RE.findall(text):
                self.send(address, what)
        if "delete_file" in self.names:
            for path in DELETE_RE.findall(text):
                if self._once(("delete", path)):
                    self._note(f"delete {path}", self.call("delete_file", path=path))

    def transfer(self, account: str, amount: float, reference: str) -> None:
        if not self._once(("transfer", f"{account}:{amount:.2f}")):
            return
        args: dict[str, Any] = {"to_account": account, "amount": amount}
        if reference:
            args["reference"] = reference
        self._note(f"transfer {amount:.2f} to {account}", self.call("transfer", **args))

    def send(self, address: str, what: str) -> None:
        if not self._once(("send", f"{address}:{what.lower()}")):
            return
        if "summary" in what.lower():
            subject, body = "Summary", self.summary()
        else:
            content = self.read_file(what)
            if content is None:
                self.log.append(f"send {what} to {address}: could not read it")
                return
            subject, body = what, content
        self._note(
            f"email {subject!r} to {address}", self.call("send_email", to=address, subject=subject, body=body), "sent"
        )

    def run(self) -> str:
        if "list_payees" in self.names and PAY_TASK_RE.search(self.task):
            self.call("list_payees")
        if "get_balance" in self.names and BALANCE_TASK_RE.search(self.task):
            self.check_balance()
        if "list_emails" in self.names and re.search(r"\b(?:inbox|emails|messages)\b", self.task, re.IGNORECASE):
            self.read_inbox()
        if "list_files" in self.names and re.search(r"\b(?:files?|drive|folder|notes)\b", self.task, re.IGNORECASE):
            self.read_drive()
        # The vulnerability: everything the agent read is treated like the user's own instructions.
        position = 0
        while position < len(self.texts):
            self.act_on(self.texts[position][1])
            position += 1
        if self.owner and SEND_ME_RE.search(self.task):
            self.send(self.owner, "a summary")
        return "\n".join(self.log) if self.log else "Nothing to do."


def run(task: str, tools: Toolbox) -> str:
    """Entry point used by `agentbreak run --agent inbox-assistant`."""
    return _Assistant(task, tools).run()
