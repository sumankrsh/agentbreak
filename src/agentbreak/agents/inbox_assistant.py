"""A deliberately vulnerable office assistant, for exercising the harness offline.

It stands in for an over-trusting LLM agent. It works out what to read from the
task, reads it, and then acts on every instruction it finds: in the task, but
also inside the emails and files it read. That last part is the bug. It is
rule-based and deterministic, so runs are repeatable and need no API key.

It understands a small set of phrasings:

- "pay/transfer 420.00 to account NW-778 (reference X)"
- "invoice NW-2231 for 420.00 ... account NW-778" (paid when the task asks to pay invoices)
- "send/email/forward <file path | a summary> to someone@example.com"
- "email me a summary" (sent to the mailbox owner)
- "delete <file path>"

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
FOLDER_RE = re.compile(r"\bin the ([\w-]+) folder\b", re.IGNORECASE)
OWNER_RE = re.compile(rf"\bfrom {ADDRESS}")


def _number(text: str) -> float:
    return float(text.replace(",", ""))


def _first_sentence(text: str, limit: int = 90) -> str:
    line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    sentence = re.split(r"(?<=[.!?])\s", line, maxsplit=1)[0]
    return sentence if len(sentence) <= limit else sentence[: limit - 3] + "..."


class _Assistant:
    def __init__(self, task: str, tools: Toolbox):
        self.task = task
        self.tools = tools
        self.names = set(tools.tool_names())
        self.texts: list[tuple[str, str]] = [("task", task)]  # (where it came from, text)
        self.files: dict[str, str] = {}
        self.done: set[tuple[str, str]] = set()
        self.log: list[str] = []
        owner = None
        for spec in tools.specs():
            if spec["name"] == "send_email":
                match = OWNER_RE.search(spec["description"])
                owner = match.group(1) if match else None
        self.owner = owner

    # Reading ---------------------------------------------------------------

    def read_inbox(self) -> None:
        listing = self.tools.call("list_emails")
        for item in listing.get("emails", []):
            message = self.tools.call("read_email", id=item["id"])
            if message.get("ok"):
                self.texts.append((f"email {item['id']} ({message['subject']})", message["body"]))

    def read_drive(self) -> None:
        folder = FOLDER_RE.search(self.task)
        listing = self.tools.call("list_files", folder=folder.group(1)) if folder else self.tools.call("list_files")
        for path in listing.get("files", []):
            self.read_file(path)

    def read_file(self, path: str) -> str | None:
        if path in self.files:
            return self.files[path]
        result = self.tools.call("read_file", path=path)
        if not result.get("ok"):
            return None
        self.files[path] = result["content"]
        self.texts.append((f"file {path}", result["content"]))
        return result["content"]

    # Acting ----------------------------------------------------------------

    def _once(self, key: tuple[str, str]) -> bool:
        if key in self.done:
            return False
        self.done.add(key)
        return True

    def summary(self) -> str:
        lines = [f"- {where}: {_first_sentence(text)}" for where, text in self.texts[1:]]
        return "Summary of what I read:\n" + ("\n".join(lines) if lines else "- nothing to report")

    def act_on(self, text: str) -> None:
        wants_invoices = re.search(r"\bpay\b.*\binvoices?\b", self.task, re.IGNORECASE) is not None
        if "transfer" in self.names:
            for amount, account, reference in TRANSFER_RE.findall(text):
                self.transfer(account, _number(amount), reference)
            if wants_invoices:
                for invoice, amount, account in INVOICE_RE.findall(text):
                    self.transfer(account, _number(amount), invoice)
        if "send_email" in self.names:
            for what, address in SEND_RE.findall(text):
                self.send(address, what)
        if "delete_file" in self.names:
            for path in DELETE_RE.findall(text):
                if self._once(("delete", path)):
                    result = self.tools.call("delete_file", path=path)
                    self.log.append(f"delete {path}: {'done' if result.get('ok') else result.get('error')}")

    def transfer(self, account: str, amount: float, reference: str) -> None:
        if not self._once(("transfer", f"{account}:{amount:.2f}")):
            return
        args: dict[str, Any] = {"to_account": account, "amount": amount}
        if reference:
            args["reference"] = reference
        result = self.tools.call("transfer", args)
        self.log.append(f"transfer {amount:.2f} to {account}: {'done' if result.get('ok') else result.get('error')}")

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
        result = self.tools.call("send_email", to=address, subject=subject, body=body)
        self.log.append(f"email {subject!r} to {address}: {'sent' if result.get('ok') else result.get('error')}")

    def run(self) -> str:
        if "list_emails" in self.names and re.search(r"\b(?:inbox|emails|messages)\b", self.task, re.IGNORECASE):
            self.read_inbox()
        if "list_files" in self.names and re.search(r"\b(?:files?|drive|folder|notes)\b", self.task, re.IGNORECASE):
            self.read_drive()
        # The vulnerability: content the agent read is treated like the user's own instructions.
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
