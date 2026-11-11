"""Serve a scenario's sandbox tools over the Model Context Protocol (MCP).

An MCP client connects, lists the tools and calls them, exactly as it would
call a real server. Behind the protocol is the same recording `Toolbox` the
Python agents get, so every call is recorded and judged the same way.

The transport is the MCP stdio framing: one JSON-RPC 2.0 message per line.
Only what a tools-only server needs is implemented: `initialize`, `ping`,
`tools/list` and `tools/call`, plus the notifications a client sends.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, TextIO

from . import __version__
from .sandbox import CallLimitReached, Toolbox

# Newest first. A client asking for one of these gets it; otherwise the newest.
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
CALL_LIMIT = -32000


class MCPServer:
    """Answers MCP JSON-RPC messages from a `Toolbox`.

    `handle` takes one decoded message and returns the response to send, or
    None for a notification. It never raises for bad input.
    """

    def __init__(self, toolbox: Toolbox, name: str = "agentbreak-sandbox"):
        self.toolbox = toolbox
        self.name = name
        self.protocol_version: str | None = None
        self.client: dict[str, Any] = {}
        self.limit_reached = False

    def tools(self) -> list[dict[str, Any]]:
        return [
            {"name": s["name"], "description": s["description"], "inputSchema": s["input_schema"]}
            for s in self.toolbox.specs()
        ]

    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "method" not in message:
            if isinstance(message, dict) and "method" not in message and ("result" in message or "error" in message):
                return None  # a response to something we never asked; ignore it
            return _error(message.get("id") if isinstance(message, dict) else None, INVALID_REQUEST, "invalid request")
        method = message["method"]
        params = message.get("params") or {}
        if "id" not in message:
            return None  # notifications/initialized, notifications/cancelled, ...
        request_id = message["id"]
        if not isinstance(params, dict):
            return _error(request_id, INVALID_PARAMS, "params must be an object")
        if method == "initialize":
            return _result(request_id, self._initialize(params))
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            return _result(request_id, {"tools": self.tools()})
        if method == "tools/call":
            return self._call(request_id, params)
        return _error(request_id, METHOD_NOT_FOUND, f"method not found: {method}")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        asked = params.get("protocolVersion")
        self.protocol_version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        info = params.get("clientInfo")
        self.client = dict(info) if isinstance(info, dict) else {}
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.name, "version": __version__},
            "instructions": "Tools for the task you were given.",
        }

    def _call(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not name:
            return _error(request_id, INVALID_PARAMS, "tools/call needs a tool name")
        if not isinstance(arguments, dict):
            return _error(request_id, INVALID_PARAMS, "arguments must be an object")
        try:
            outcome = self.toolbox.call(name, arguments)
        except CallLimitReached as exc:
            self.limit_reached = True
            return _error(request_id, CALL_LIMIT, str(exc))
        payload = {k: v for k, v in outcome.items() if k != "ok"}
        text = payload["error"] if not outcome["ok"] else json.dumps(payload, sort_keys=False)
        return _result(
            request_id,
            {
                "content": [{"type": "text", "text": text}],
                "structuredContent": payload,
                "isError": not outcome["ok"],
            },
        )


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle_line(server: MCPServer, line: str) -> str | None:
    """Decode one line, handle it and encode the reply (None when there is nothing to send)."""
    if not line.strip():
        return None
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        return json.dumps(_error(None, PARSE_ERROR, "parse error"))
    reply = server.handle(message)
    return None if reply is None else json.dumps(reply, default=str)


def serve_lines(
    server: MCPServer,
    readline: Callable[[], str],
    write: Callable[[str], None],
    stop: Callable[[], bool] = lambda: False,
) -> None:
    """Serve until end of input, or until `stop()` is true after a reply."""
    while True:
        line = readline()
        if not line:
            return
        reply = handle_line(server, line)
        if reply is not None:
            write(reply + "\n")
        if server.limit_reached or stop():
            return


def serve_stdio(server: MCPServer, stdin: TextIO, stdout: TextIO) -> None:
    def write(text: str) -> None:
        stdout.write(text)
        stdout.flush()

    serve_lines(server, stdin.readline, write)
