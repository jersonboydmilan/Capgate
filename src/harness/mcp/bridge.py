"""`harness mcp-bridge`: expose the harness MCP endpoint to stdio-only MCP clients.

    harness mcp-bridge --url http://proxy:8080/mcp --token-file /run/agent/token

Runs on the agent's side of the boundary. It is a pure transport adapter: it
forwards each JSON-RPC line from stdin to POST /mcp with the agent's own token
(re-read on every request, so a supervisor can rotate it) and writes the reply
to stdout. It holds no authority of its own.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, TextIO


def run_bridge(url: str, token: Callable[[], str], *, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout, timeout: float = 60.0) -> int:
    protocol_version: str | None = None
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _write(stdout, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}})
            continue
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {token()}"}
        if protocol_version and not (isinstance(message, dict) and message.get("method") == "initialize"):
            headers["MCP-Protocol-Version"] = protocol_version
        request = urllib.request.Request(url, data=line.encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            if not raw.strip().startswith(b"{"):
                raw = json.dumps({"jsonrpc": "2.0", "id": _id(message), "error": {"code": -32000, "message": f"harness returned HTTP {exc.code}"}}).encode()
        except OSError as exc:
            raw = json.dumps({"jsonrpc": "2.0", "id": _id(message), "error": {"code": -32000, "message": f"cannot reach harness: {exc}"}}).encode()
        if not raw.strip():
            continue  # notification accepted (202, no body)
        try:
            reply = json.loads(raw)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": _id(message), "error": {"code": -32000, "message": "harness returned a non-JSON reply"}}
        if isinstance(reply, dict) and "jsonrpc" not in reply:  # plain API error (401, 429, …): wrap as JSON-RPC
            if "id" not in (message if isinstance(message, dict) else {}):
                continue
            reply = {"jsonrpc": "2.0", "id": _id(message), "error": {"code": -32000, "message": str(reply.get("error", reply))}}
        if isinstance(message, dict) and message.get("method") == "initialize":
            protocol_version = ((reply.get("result") or {}) if isinstance(reply, dict) else {}).get("protocolVersion")
        _write(stdout, reply)
    return 0


def _write(stdout: TextIO, message: dict) -> None:
    stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    stdout.flush()


def _id(message: object) -> object:
    return message.get("id") if isinstance(message, dict) else None


def token_from_file(path: str) -> Callable[[], str]:
    return lambda: Path(path).read_text(encoding="utf-8").strip()
