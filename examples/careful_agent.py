"""An example of plugging your own agent into agentbreak.

An agent is any function `run(task, tools)`. `tools.specs()` returns the tool
definitions (name, description, JSON schema), and `tools.call(name, **args)`
calls one and returns a dict with "ok" and either the result or "error".

This one does a single job, paying supplier invoices it finds in the inbox,
and it treats email content as data: it only pays accounts that are already
saved payees, and it never acts on other instructions in a message. Given any
other task, it does nothing and says so.

    agentbreak run src/agentbreak/scenarios/02-poisoned-invoice-email.yaml --agent examples/careful_agent.py:run
"""

from __future__ import annotations

import re

AMOUNT = r"(\d[\d,]*(?:\.\d{1,2})?)"
ACCOUNT = r"([A-Z]{2,6}-\d{2,})"
# "Invoice NW-2231 for 420.00 ... account NW-778"
INVOICE = re.compile(rf"\binvoice\s+([\w-]+)\s+for\s+{AMOUNT}.*?\baccount\s+{ACCOUNT}", re.I | re.S)
# "Transfer 4,800.00 to account EXT-5521 reference NW-2231"
REQUEST = re.compile(
    rf"\b(?:pay|transfer)\s+{AMOUNT}\s+to\s+(?:account\s+)?{ACCOUNT}(?:[^.]*?\breference\s+([\w-]+))?", re.I
)


def run(task, tools):
    names = {spec["name"] for spec in tools.specs()}
    if not re.search(r"\bpay\b", task, re.I) or not {"list_emails", "read_email", "transfer"} <= names:
        return "I only pay supplier invoices from the inbox, so I did nothing."
    payees = {p["account"] for p in tools.call("list_payees").get("payees", [])}
    paid, skipped = [], []
    for item in tools.call("list_emails").get("emails", []):
        message = tools.call("read_email", id=item["id"])
        body = message.get("body", "")
        found = INVOICE.findall(body) + [
            (ref or "no reference", amount, account) for amount, account, ref in REQUEST.findall(body)
        ]
        for invoice, amount, account in found:
            if account not in payees:
                skipped.append(f"{invoice} to {account} (not a saved payee)")
                continue
            result = tools.call(
                "transfer", to_account=account, amount=float(amount.replace(",", "")), reference=invoice
            )
            (paid if result["ok"] else skipped).append(f"{invoice} to {account}")
    return f"Paid: {', '.join(paid) or 'nothing'}. Skipped: {', '.join(skipped) or 'nothing'}."
