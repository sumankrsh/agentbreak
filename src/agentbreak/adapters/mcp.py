"""Test an agent that runs as its own program and gets its tools from an MCP server.

`MCPCommandAgent` runs the agent's command once per scenario. The agent is
given an MCP config file whose only server is agentbreak. When the agent starts
that server, it starts `agentbreak mcp relay`, a small process that passes the
MCP messages back to this process over a local socket, where the scenario's
sandbox answers and records them. So the agent talks the real protocol, in any
language, and the calls are judged exactly like a Python agent's.

    agentbreak run scenario.yaml --agent "mcp:node my-agent.js --mcp-config {mcp_config} --prompt {task}"

The command is split like a shell would split it, but it is not run through a
shell. `{task}` and `{mcp_config}` are replaced inside each argument. The agent
also gets the environment variables AGENTBREAK_TASK, AGENTBREAK_MCP_CONFIG and
AGENTBREAK_MCP_COMMAND (the server command as a JSON list).
"""

from __future__ import annotations

import json
import os
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, TextIO

from ..mcp_server import MCPServer, serve_lines
from ..sandbox import CallLimitReached, Toolbox

PREFIX = "mcp:"
TIMEOUT_ENV = "AGENTBREAK_AGENT_TIMEOUT"
DEFAULT_TIMEOUT = 120.0


class AgentProcessError(RuntimeError):
    """The agent's process failed, timed out or couldn't be started."""


def _timeout() -> float:
    raw = os.environ.get(TIMEOUT_ENV)
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except ValueError as exc:
        raise AgentProcessError(f"{TIMEOUT_ENV} must be a number of seconds, not {raw!r}") from exc
    if value <= 0:
        raise AgentProcessError(f"{TIMEOUT_ENV} must be more than 0")
    return value


def _tail(text: str, lines: int = 5) -> str:
    kept = [ln for ln in text.strip().splitlines() if ln.strip()][-lines:]
    return " | ".join(kept)


class _Bridge:
    """The local socket the relay connects to. Each connection is one MCP session on the same toolbox."""

    def __init__(self, toolbox: Toolbox):
        self.toolbox = toolbox
        self.token = secrets.token_hex(16)
        self.lock = threading.Lock()
        self.limit_reached = threading.Event()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.address = f"127.0.0.1:{self.listener.getsockname()[1]}"
        self.connections: list[socket.socket] = []
        self.sessions: list[MCPServer] = []
        self.closed = False
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self) -> None:
        while not self.closed:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.connections.append(conn)
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn: socket.socket) -> None:
        reader = conn.makefile("r", encoding="utf-8", newline="\n")
        try:
            if reader.readline().strip() != self.token:
                return
            server = MCPServer(self.toolbox)
            self.sessions.append(server)

            def write(text: str) -> None:
                conn.sendall(text.encode("utf-8"))

            serve_lines(_LockedServer(server, self.lock), reader.readline, write)  # type: ignore[arg-type]
            if server.limit_reached:
                self.limit_reached.set()
        except OSError:
            return
        finally:
            reader.close()
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self.closed = True
        try:
            self.listener.close()
        except OSError:
            pass
        for conn in self.connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass


class _LockedServer:
    """Wraps an MCPServer so sessions sharing a toolbox handle one message at a time."""

    def __init__(self, server: MCPServer, lock: threading.Lock):
        self._server = server
        self._lock = lock

    def handle(self, message: Any) -> dict[str, Any] | None:
        with self._lock:
            return self._server.handle(message)

    @property
    def limit_reached(self) -> bool:
        return self._server.limit_reached


class MCPCommandAgent:
    """An agent that is an external command using agentbreak as its MCP server."""

    def __init__(self, command: str, cwd: Path | None = None):
        command = command.strip()
        if not command:
            raise ValueError("an mcp: agent needs a command, for example mcp:python my_agent.py {task}")
        try:
            self.argv = shlex.split(command)
        except ValueError as exc:
            raise ValueError(f"can't split the agent command: {exc}") from exc
        self.command = command
        self.cwd = cwd

    def __repr__(self) -> str:
        return f"MCPCommandAgent({self.command!r})"

    def server_command(self, address: str, token: str) -> list[str]:
        return [sys.executable, "-m", "agentbreak", "mcp", "relay", address, token]

    def __call__(self, task: str, tools: Toolbox) -> str:
        timeout = _timeout()
        bridge = _Bridge(tools)
        try:
            with tempfile.TemporaryDirectory(prefix="agentbreak-mcp-") as tmp:
                server = self.server_command(bridge.address, bridge.token)
                config = Path(tmp) / "mcp.json"
                config.write_text(
                    json.dumps({"mcpServers": {"agentbreak": {"command": server[0], "args": server[1:]}}}, indent=2),
                    encoding="utf-8",
                )
                argv = [a.replace("{task}", task).replace("{mcp_config}", str(config)) for a in self.argv]
                env = {
                    **os.environ,
                    "AGENTBREAK_TASK": task,
                    "AGENTBREAK_MCP_CONFIG": str(config),
                    "AGENTBREAK_MCP_COMMAND": json.dumps(server),
                }
                return self._run(argv, env, bridge, timeout)
        finally:
            bridge.close()

    def _run(self, argv: list[str], env: dict[str, str], bridge: _Bridge, timeout: float) -> str:
        try:
            proc = subprocess.Popen(
                argv,
                cwd=self.cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise AgentProcessError(f"can't start {argv[0]!r}: {exc.strerror or exc}") from exc
        waited = 0.0
        step = 0.1
        while True:
            try:
                out, errs = proc.communicate(timeout=step)
                break
            except subprocess.TimeoutExpired:
                waited += step
                if bridge.limit_reached.is_set():
                    proc.kill()
                    proc.communicate()
                    raise CallLimitReached(f"the agent made more than {bridge.toolbox.max_calls} tool calls") from None
                if waited >= timeout:
                    proc.kill()
                    proc.communicate()
                    raise AgentProcessError(f"the agent did not finish within {timeout:g} seconds") from None
        if bridge.limit_reached.is_set():
            raise CallLimitReached(f"the agent made more than {bridge.toolbox.max_calls} tool calls")
        if proc.returncode != 0:
            detail = _tail(errs) or _tail(out) or "no output"
            raise AgentProcessError(f"the agent exited with status {proc.returncode}: {detail}")
        return out.strip()


def relay(address: str, token: str, stdin: TextIO, stdout: TextIO) -> int:
    """Pass MCP messages between stdin/stdout and the agentbreak process at `address`."""
    host, _, port = address.rpartition(":")
    try:
        conn = socket.create_connection((host, int(port)), timeout=10)
    except (OSError, ValueError) as exc:
        print(f"agentbreak relay: can't reach {address}: {exc}", file=sys.stderr)
        return 1
    conn.settimeout(None)
    conn.sendall((token + "\n").encode("utf-8"))

    def pump_in() -> None:
        try:
            for line in iter(stdin.readline, ""):
                conn.sendall(line.encode("utf-8") if line.endswith("\n") else (line + "\n").encode("utf-8"))
        except OSError:
            pass
        finally:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=pump_in, daemon=True).start()
    reader = conn.makefile("r", encoding="utf-8", newline="\n")
    try:
        for line in iter(reader.readline, ""):
            stdout.write(line)
            stdout.flush()
    except OSError:
        pass
    finally:
        reader.close()
        conn.close()
    return 0
