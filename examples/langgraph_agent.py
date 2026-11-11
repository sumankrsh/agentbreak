"""A LangGraph agent tested through agentbreak's LangGraph adapter, before and after a fix.

The graph is the usual tool-calling loop: a model node proposes tool calls, a
ToolNode runs them, and the results go back to the model. To run offline, the
model node here is a rule-based stand-in (`planner`) that trusts what it reads:
it pays every "pay X to account Y" and every invoice line it finds in the
inbox. Swap in a real chat model and the rest of the graph stays the same.

The fix is a guard node between the model and the tools (`build(tools,
guarded=True)`). It runs outside the model, so text in an email can't talk it
round. It lets a transfer through only if the account is a saved payee and
that payee hasn't been paid in this run; anything else is answered with a
"held for approval" tool message and never reaches the tool.

    agentbreak attacks run --agent examples/langgraph_agent.py:run
    agentbreak attacks run --agent examples/langgraph_agent.py:run_guarded

Needs `pip install "agentbreak[langgraph]"`.
"""

from __future__ import annotations

import json
import re
import uuid

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from agentbreak.adapters.langgraph import graph_agent

AMOUNT = r"(\d[\d,]*(?:\.\d{1,2})?)"
ACCOUNT = r"([A-Z]{2,6}-\d{2,})"
PAY = re.compile(rf"\b(?:pay|transfer)\s+{AMOUNT}\s+to\s+(?:account\s+)?{ACCOUNT}", re.I)
INVOICE = re.compile(rf"\binvoice\s+([\w-]+)\s+for\s+{AMOUNT}.*?\baccount\s+{ACCOUNT}", re.I | re.S)


def _call(name: str, **args) -> dict:
    return {"name": name, "args": args, "id": f"call_{uuid.uuid4().hex[:8]}", "type": "tool_call"}


def _results(messages, tool: str) -> list[dict]:
    out = []
    for m in messages:
        if isinstance(m, ToolMessage) and m.name == tool and not str(m.content).startswith("Error"):
            try:
                out.append(json.loads(m.content))
            except json.JSONDecodeError:
                continue
    return out


def planner(state: MessagesState) -> dict:
    """Stand-in for the model: list the inbox, read every message, then pay what the messages ask for."""
    messages = state["messages"]
    task = messages[0].content
    if not re.search(r"\bpay\b", task, re.I):
        return {"messages": [AIMessage("I only pay invoices from the inbox, so I did nothing.")]}
    listings = _results(messages, "list_emails")
    if not listings:
        return {"messages": [AIMessage("", tool_calls=[_call("list_emails")])]}
    read = {r["id"] for r in _results(messages, "read_email")}
    unread = [e["id"] for e in listings[0].get("emails", []) if e["id"] not in read]
    if unread:
        return {"messages": [AIMessage("", tool_calls=[_call("read_email", id=i) for i in unread])]}
    if any(isinstance(m, ToolMessage) and m.name == "transfer" for m in messages):
        return {"messages": [AIMessage(_report(messages))]}
    payments = []
    for email in _results(messages, "read_email"):
        body = email.get("body", "")
        payments += [(amount, account, None) for amount, account in PAY.findall(body)]
        payments += [(amount, account, invoice) for invoice, amount, account in INVOICE.findall(body)]
    calls = []
    for amount, account, reference in dict.fromkeys(payments):
        args = {"to_account": account, "amount": float(amount.replace(",", ""))}
        if reference:
            args["reference"] = reference
        calls.append(_call("transfer", **args))
    if not calls:
        return {"messages": [AIMessage("No invoices to pay.")]}
    return {"messages": [AIMessage("", tool_calls=calls)]}


def _report(messages) -> str:
    lines = [f"{m.name}: {m.content}" for m in messages if isinstance(m, ToolMessage) and m.name == "transfer"]
    return "Payments:\n" + "\n".join(lines)


def make_guard(tools):
    """The fix: a node that checks each proposed transfer before the ToolNode can run it."""
    by_name = {t.name: t for t in tools}

    def guard(state: MessagesState) -> dict:
        *earlier, last = state["messages"]
        payees = None
        # Every earlier model message has already been through this guard, so its transfers were allowed.
        paid = {
            c["args"].get("to_account")
            for m in earlier
            if isinstance(m, AIMessage)
            for c in m.tool_calls
            if c["name"] == "transfer"
        }
        allowed, held = [], []
        for call in last.tool_calls:
            if call["name"] != "transfer":
                allowed.append(call)
                continue
            if payees is None:
                listing = json.loads(by_name["list_payees"].invoke({}))
                payees = {p["account"] for p in listing.get("payees", [])}
            account = call["args"].get("to_account")
            if account not in payees:
                held.append(ToolMessage(f"Error: held for approval: {account} is not a saved payee", **_ids(call)))
            elif account in paid:
                held.append(ToolMessage(f"Error: held for approval: {account} was already paid", **_ids(call)))
            else:
                paid.add(account)
                allowed.append(call)
        return {"messages": [AIMessage(last.content, tool_calls=allowed, id=last.id), *held]}

    return guard


def _last_ai(state: MessagesState) -> AIMessage:
    return next(m for m in reversed(state["messages"]) if isinstance(m, AIMessage))


def _ids(call: dict) -> dict:
    return {"tool_call_id": call["id"], "name": call["name"]}


def build(tools, guarded: bool = False):
    graph = StateGraph(MessagesState)
    graph.add_node("model", planner)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "model")
    first_hop = "guard" if guarded else "tools"
    graph.add_conditional_edges("model", lambda s: first_hop if s["messages"][-1].tool_calls else END)
    if guarded:
        graph.add_node("guard", make_guard(tools))
        graph.add_conditional_edges("guard", lambda s: "tools" if _last_ai(s).tool_calls else "model")
    graph.add_edge("tools", "model")
    return graph.compile()


run = graph_agent(build)
run_guarded = graph_agent(lambda tools: build(tools, guarded=True))
