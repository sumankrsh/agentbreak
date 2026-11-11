"""Test a LangGraph (or any LangChain-tool) agent against agentbreak's sandbox.

`langchain_tools(tools)` turns the sandbox toolbox into LangChain tools, with
the scenario's tool descriptions (poisoned ones included) and JSON schemas.
`graph_agent(build)` wraps a function that builds your graph from those tools
into an agent `run(task, tools)` that agentbreak can run:

    from agentbreak.adapters.langgraph import graph_agent
    from langgraph.prebuilt import create_react_agent

    run = graph_agent(lambda tools: create_react_agent(my_model, tools))

Needs `langchain-core` (installed with `pip install "agentbreak[langgraph]"`).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ..sandbox import Toolbox


class MissingDependency(ImportError):
    """LangChain isn't installed."""


def _core() -> Any:
    try:
        from langchain_core import tools as lc_tools
    except ImportError as exc:  # pragma: no cover - exercised only without the extra installed
        raise MissingDependency(
            'the LangGraph adapter needs langchain-core: pip install "agentbreak[langgraph]"'
        ) from exc
    return lc_tools


def _as_text(result: dict[str, Any]) -> str:
    """What the model sees: the result as JSON, or the error, as a tool message would carry it."""
    if not result.get("ok"):
        return f"Error: {result.get('error', 'the tool failed')}"
    return json.dumps({k: v for k, v in result.items() if k != "ok"})


def langchain_tools(tools: Toolbox) -> list[Any]:
    """One LangChain `StructuredTool` per sandbox tool. Each call goes through `tools.call` and is recorded."""
    lc_tools = _core()
    built = []
    for spec in tools.specs():
        name = spec["name"]

        def call(_name: str = name, **kwargs: Any) -> str:
            return _as_text(tools.call(_name, kwargs))

        built.append(
            lc_tools.StructuredTool(
                name=name,
                description=spec["description"],
                args_schema=spec["input_schema"],
                func=call,
            )
        )
    return built


def graph_agent(build: Callable[[list[Any]], Any], recursion_limit: int = 50) -> Callable[[str, Toolbox], str]:
    """Make an agentbreak agent from a function that builds a compiled graph from a list of tools.

    The graph is invoked with `{"messages": [("user", task)]}`, the input shape of
    LangGraph's message-based agents, and the content of its last message is the answer.
    """

    def run(task: str, tools: Toolbox) -> str:
        graph = build(langchain_tools(tools))
        state = graph.invoke({"messages": [("user", task)]}, {"recursion_limit": recursion_limit})
        messages = state.get("messages", []) if isinstance(state, dict) else []
        if not messages:
            return ""
        content = getattr(messages[-1], "content", messages[-1])
        return content if isinstance(content, str) else json.dumps(content, default=str)

    run.__wrapped__ = build  # type: ignore[attr-defined]  # so reports point at the user's builder
    return run
