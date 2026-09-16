"""Built-in executor tools.

Tools run inside the executor and are the only code that holds credentials.
`ControlledEndpointTool` is the reference integration for the enforced
boundary: the real tool lives behind an HTTP endpoint that accepts only the
executor's credential, and agents never receive that credential.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from .secretsource import read_secret


class EchoTool:
    """Returns its arguments. Useful for demos and tests."""

    def __call__(self, arguments: dict[str, Any]) -> Any:
        return {"echo": arguments}


class ControlledEndpointTool:
    """POSTs the authorized arguments to a controlled tool endpoint."""

    def __init__(self, url: str, credential: str, *, timeout: float = 10.0) -> None:
        if not credential:
            raise ValueError("a controlled endpoint requires a credential")
        self.url = url
        self._credential = credential
        self.timeout = timeout

    def __repr__(self) -> str:  # never leak the credential through logs or tracebacks
        return f"ControlledEndpointTool(url={self.url!r}, credential=<redacted>)"

    def __call__(self, arguments: dict[str, Any]) -> Any:
        req = urllib.request.Request(
            self.url,
            data=json.dumps(arguments).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._credential}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"tool endpoint returned HTTP {exc.code}") from None


class HttpFetchTool:
    """GETs a URL. Pair with allowed_domains / block_private_hosts constraints.

    Note: host checks happen at policy time on the URL string; DNS rebinding
    and redirects to private addresses are not prevented here. Deploy with an
    egress proxy if the fetched hosts are untrusted (see docs/threat-model.md).
    """

    def __init__(self, *, max_bytes: int = 256_000, timeout: float = 10.0) -> None:
        self.max_bytes = max_bytes
        self.timeout = timeout

    def __call__(self, arguments: dict[str, Any]) -> Any:
        url = arguments["url"]
        req = urllib.request.Request(url, headers={"User-Agent": "agent-harness/0.1"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read(self.max_bytes)
            return {"status": resp.status, "url": resp.geturl(), "body": body.decode("utf-8", errors="replace")}


def build_tools(spec: Mapping[str, Any] | None, *, base: Path | None = None) -> dict[str, Any]:
    """Build tools from a config mapping:

        tools:
          web.search: {type: echo}
          database.write: {type: endpoint, url: http://127.0.0.1:9100/db, credential_file: /run/secrets/tool_credential}
          # or credential_env: DB_TOOL_TOKEN
          web.fetch: {type: http_fetch}
    """
    tools: dict[str, Any] = {}
    for action, cfg in (spec or {}).items():
        kind = (cfg or {}).get("type")
        if kind == "echo":
            tools[action] = EchoTool()
        elif kind == "http_fetch":
            tools[action] = HttpFetchTool()
        elif kind == "endpoint":
            tools[action] = ControlledEndpointTool(cfg["url"], read_secret(cfg, "credential", f"tool {action}", base=base))
        else:
            raise ValueError(f"tool {action}: unknown type {kind!r} (expected echo, endpoint or http_fetch)")
    return tools
