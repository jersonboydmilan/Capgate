"""Built-in executor tools.

Tools run inside the executor and are the only code that holds credentials.
`ControlledEndpointTool` is the reference integration for the enforced
boundary: the real tool lives behind an HTTP endpoint that accepts only the
executor's credential, and agents never receive that credential.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .netaddr import InvalidHost, ip_literal, is_public_ip, normalize_hostname
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


class DestinationRefused(PermissionError):
    pass


def _system_resolver(host: str, port: int) -> list[str]:
    return list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, **kwargs: Any) -> None:
        super().__init__(host, port, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, **kwargs: Any) -> None:
        super().__init__(host, port, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        # Certificate verification and SNI use the hostname; the TCP connection uses the vetted IP.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class HttpFetchTool:
    """GETs a URL with destination checks that hold at connection time.

    Policy constraints (`allowed_domains`, `block_private_hosts`) judge the URL
    text. This tool closes the gap between that text and the socket:

    * resolves the host once and refuses if **any** address is non-public
      (loopback, private, link-local, metadata, IPv4-mapped/6to4/Teredo to those);
    * connects to the vetted address, so a second DNS answer (rebinding) is never used;
    * refuses URLs with embedded credentials and ports outside `allowed_ports`;
    * does **not** follow redirects: it returns the `Location`, and following it
      is a new `web.fetch` proposal that policy evaluates again.
    """

    def __init__(
        self,
        *,
        max_bytes: int = 256_000,
        timeout: float = 10.0,
        allow_private: bool = False,
        allowed_ports: tuple[int, ...] | None = (80, 443),
        resolver: Callable[[str, int], list[str]] = _system_resolver,
    ) -> None:
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.allow_private = allow_private
        self.allowed_ports = allowed_ports
        self._resolve = resolver

    def __call__(self, arguments: dict[str, Any]) -> Any:
        url = arguments["url"]
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise DestinationRefused("only http(s) URLs with a host are fetched")
        if parts.username is not None or parts.password is not None:
            raise DestinationRefused("URLs with embedded credentials are refused")
        try:
            host = normalize_hostname(parts.hostname)
        except InvalidHost as exc:
            raise DestinationRefused(str(exc)) from None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if self.allowed_ports is not None and port not in self.allowed_ports:
            raise DestinationRefused(f"port {port} is not allowed")

        literal = ip_literal(host)
        addresses = [str(literal)] if literal is not None else self._resolve(host, port)
        if not addresses:
            raise DestinationRefused(f"{host!r} did not resolve")
        if not self.allow_private:
            for address in addresses:
                if not is_public_ip(ipaddress.ip_address(address.split("%")[0])):
                    raise DestinationRefused(f"{host!r} resolves to non-public address {address}")
        pinned = addresses[0]

        conn_cls = _PinnedHTTPSConnection if parts.scheme == "https" else _PinnedHTTPConnection
        conn = conn_cls(host, port, pinned, timeout=self.timeout)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        try:
            conn.request("GET", path, headers={"User-Agent": "agent-harness/0.1", "Accept-Encoding": "identity"})
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                return {"status": resp.status, "url": url, "resolved_ip": pinned, "redirect_to": resp.getheader("Location"), "followed": False, "body": ""}
            body = resp.read(self.max_bytes + 1)
            return {
                "status": resp.status,
                "url": url,
                "resolved_ip": pinned,
                "body": body[: self.max_bytes].decode("utf-8", errors="replace"),
                "truncated": len(body) > self.max_bytes,
            }
        finally:
            conn.close()


def build_tools(spec: Mapping[str, Any] | None, *, base: Path | None = None, mcp_servers: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build tools from a config mapping:

        tools:
          web.search: {type: echo}
          database.write: {type: endpoint, url: http://127.0.0.1:9100/db, credential_file: /run/secrets/tool_credential}
          # or credential_env: DB_TOOL_TOKEN
          web.fetch: {type: http_fetch}
    """
    tools: dict[str, Any] = {}
    clients = None
    for action, cfg in (spec or {}).items():
        kind = (cfg or {}).get("type")
        if kind == "echo":
            tools[action] = EchoTool()
        elif kind == "http_fetch":
            tools[action] = HttpFetchTool()
        elif kind == "endpoint":
            tools[action] = ControlledEndpointTool(cfg["url"], read_secret(cfg, "credential", f"tool {action}", base=base))
        elif kind == "mcp":
            from .mcp.upstream import MCPTool, build_mcp_clients

            if clients is None:
                clients = build_mcp_clients(mcp_servers, base=base)
            server = cfg.get("server")
            if server not in clients:
                raise ValueError(f"tool {action}: unknown mcp server {server!r}")
            tools[action] = MCPTool(clients[server], cfg.get("tool") or action.rsplit(".", 1)[-1])
        else:
            raise ValueError(f"tool {action}: unknown type {kind!r} (expected echo, endpoint, http_fetch or mcp)")
    return tools
