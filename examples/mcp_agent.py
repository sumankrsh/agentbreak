"""An agent that runs as its own program and gets its tools from an MCP server.

It stands in for any MCP-based agent: it reads a standard MCP config file
(`{"mcpServers": {...}}`), starts the server named there, speaks MCP over
stdio (initialize, tools/list, tools/call) and decides what to do with the
logic of one of the two example agents next to it. It uses only the Python
standard library, so nothing about it depends on agentbreak.

Test it with agentbreak serving the tools:

    agentbreak ci --agent "mcp:python examples/mcp_agent.py --mcp-config {mcp_config} --logic careful {task}"

agentbreak replaces {mcp_config} with a config whose only server is
agentbreak, and {task} with the scenario's task.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


class MCPClient:
    """A minimal MCP client over stdio: one JSON-RPC message per line."""

    def __init__(self, command: str, args: list[str], env: dict[str, str] | None = None):
        self.proc = subprocess.Popen(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=env,
        )
        self.next_id = 0

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError(f"the MCP server closed during {method}")
            message = json.loads(line)
            if message.get("id") == self.next_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error'].get('message')}")
                return message["result"]

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def _send(self, message: dict[str, Any]) -> None:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def close(self) -> None:
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


class MCPTools:
    """The `tools` object the example agents expect, backed by MCP calls."""

    def __init__(self, client: MCPClient):
        self.client = client
        listed = client.request("tools/list")["tools"]
        self._specs = [
            {"name": t["name"], "description": t.get("description", ""), "input_schema": t["inputSchema"]}
            for t in listed
        ]

    def specs(self) -> list[dict[str, Any]]:
        return self._specs

    def tool_names(self) -> list[str]:
        return [s["name"] for s in self._specs]

    def call(self, name: str, arguments: dict[str, Any] | None = None, /, **kwargs: Any) -> dict[str, Any]:
        result = self.client.request("tools/call", {"name": name, "arguments": {**(arguments or {}), **kwargs}})
        data = result.get("structuredContent")
        if data is None:
            text = result["content"][0]["text"] if result.get("content") else ""
            data = {"error": text} if result.get("isError") else json.loads(text or "{}")
        return {"ok": not result.get("isError", False), **data}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("task")
    parser.add_argument("--mcp-config", required=True, help="An MCP config file with an mcpServers section.")
    parser.add_argument("--server", default="agentbreak", help="Which server in the config to use.")
    parser.add_argument("--logic", choices=["careful", "hardened"], default="careful")
    args = parser.parse_args()

    servers = json.loads(Path(args.mcp_config).read_text(encoding="utf-8"))["mcpServers"]
    server = servers[args.server]
    client = MCPClient(server["command"], server.get("args", []), server.get("env"))
    try:
        client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "example-mcp-agent", "version": "1.0"},
            },
        )
        client.notify("notifications/initialized")
        sys.path.insert(0, str(HERE))
        logic = __import__(f"{args.logic}_agent")
        print(logic.run(args.task, MCPTools(client)))
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
