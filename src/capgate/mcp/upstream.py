"""Executor tools backed by real MCP servers.

The upstream server runs as a child of the harness process (stdio transport),
so its credentials are configured here, on the harness side, and never reach
the agent. The executor calls it only with a valid permit, with exactly the
authorized arguments.

    mcp_servers:
      notes:
        command: [python3, -m, notes_server]
        env: {NOTES_TOKEN: {file: /secrets/notes_token}}
    tools:
      notes.write: {type: mcp, server: notes, tool: write_note}
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from typing import Any, Mapping

PROTOCOL_VERSION = "2025-06-18"


class UpstreamError(RuntimeError):
    pass


class MCPStdioClient:
    def __init__(self, command: list[str], *, env: Mapping[str, str] | None = None, cwd: str | None = None, timeout: float = 30.0, name: str = "upstream") -> None:
        if not command:
            raise ValueError("an MCP server needs a command")
        self.command, self.env, self.cwd, self.timeout, self.name = list(command), dict(env or {}), cwd, timeout, name
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self._next_id = 0
        self._pending: dict[int, queue.Queue] = {}
        self._tools: dict[str, dict] | None = None

    def __repr__(self) -> str:  # never print env: it holds credentials
        return f"MCPStdioClient(name={self.name!r}, command={self.command[:1]!r})"

    # -- lifecycle -------------------------------------------------------------------

    def _ensure(self) -> None:
        if self._proc and self._proc.poll() is None:
            return
        base_env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "SYSTEMROOT", "TMPDIR")}
        self._proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**base_env, **self.env}, cwd=self.cwd, text=True, bufsize=1,
        )
        self._pending.clear()
        threading.Thread(target=self._reader, args=(self._proc,), daemon=True).start()
        self._tools = None
        self._request_locked("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "capgate-executor", "version": "0.1.0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def close(self) -> None:
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            self._proc = None

    def _reader(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict):
                continue
            if "method" in message and "id" in message:
                # server -> client request (sampling, roots, elicitation): this client offers none of them
                self._send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "not supported by the harness executor"}})
                continue
            waiter = self._pending.pop(message.get("id"), None) if isinstance(message.get("id"), int) else None
            if waiter is not None:
                waiter.put(message)
        for waiter in list(self._pending.values()):
            waiter.put({"error": {"code": -32000, "message": "upstream MCP server exited"}})

    def _send(self, message: dict) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()

    def _request_locked(self, method: str, params: dict) -> Any:
        self._next_id += 1
        request_id = self._next_id
        waiter: queue.Queue = queue.Queue(maxsize=1)
        self._pending[request_id] = waiter
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        try:
            reply = waiter.get(timeout=self.timeout)
        except queue.Empty:
            self._pending.pop(request_id, None)
            raise UpstreamError(f"{self.name}: {method} timed out after {self.timeout}s") from None
        if "error" in reply:
            raise UpstreamError(f"{self.name}: {method} failed: {reply['error'].get('message')}")
        return reply.get("result")

    # -- API ------------------------------------------------------------------------------

    def request(self, method: str, params: dict) -> Any:
        with self._lock:
            self._ensure()
            return self._request_locked(method, params)

    def tools(self) -> dict[str, dict]:
        if self._tools is None:
            listed, cursor = {}, None
            while True:
                result = self.request("tools/list", {"cursor": cursor} if cursor else {})
                for tool in result.get("tools", []):
                    listed[tool["name"]] = tool
                cursor = result.get("nextCursor")
                if not cursor:
                    break
            self._tools = listed
        return self._tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})


class MCPTool:
    """An executor tool that forwards the authorized call to one tool on an upstream MCP server."""

    def __init__(self, client: MCPStdioClient, tool: str) -> None:
        self.client, self.tool = client, tool

    def __repr__(self) -> str:
        return f"MCPTool({self.client.name}.{self.tool})"

    def metadata(self) -> dict | None:
        try:
            return self.client.tools().get(self.tool)
        except UpstreamError:
            return None

    def __call__(self, arguments: dict) -> Any:
        result = self.client.call_tool(self.tool, arguments)
        if not isinstance(result, dict):
            raise UpstreamError(f"{self.client.name}.{self.tool}: malformed tools/call result")
        return {"_mcp": result}


def build_mcp_clients(spec: Mapping[str, Any] | None, *, base=None) -> dict[str, MCPStdioClient]:
    from ..secretsource import read_secret

    clients = {}
    for name, cfg in (spec or {}).items():
        env = {}
        for key, source in (cfg.get("env") or {}).items():
            if isinstance(source, str):
                env[key] = source
            elif isinstance(source, Mapping) and "value" in source:
                env[key] = str(source["value"])
            elif isinstance(source, Mapping):
                env[key] = read_secret({f"secret_{k}": v for k, v in source.items()}, "secret", f"mcp_servers.{name}.env.{key}", base=base)
            else:
                raise ValueError(f"mcp_servers.{name}.env.{key}: expected a string or {{value|file|env}}")
        command = cfg.get("command")
        if not isinstance(command, list) or not all(isinstance(c, str) for c in command):
            raise ValueError(f"mcp_servers.{name}.command must be a list of strings")
        clients[name] = MCPStdioClient(command, env=env, cwd=cfg.get("cwd"), timeout=float(cfg.get("timeout", 30)), name=name)
    return clients
