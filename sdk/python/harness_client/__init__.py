"""Thin HTTP client for the harness boundary.

A convenience, not a security control: every call it makes could be made
with curl, and the harness enforces the same rules either way.

    from harness_client import HarnessClient

    client = HarnessClient("http://127.0.0.1:8700", token=os.environ["AGENT_TOKEN"])
    outcome = client.act("web.search", {"query": "..."})
    if outcome.allowed:
        print(outcome.execution["output"])
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

__all__ = ["HarnessClient", "Outcome"]


@dataclass(frozen=True)
class Outcome:
    status: int
    body: dict[str, Any] = field(default_factory=dict)

    @property
    def decision(self) -> str | None:
        return self.body.get("decision") or (self.body.get("action") or {}).get("decision") or (self.body.get("delegation") or {}).get("decision")

    @property
    def allowed(self) -> bool:
        return self.status == 200

    @property
    def escalated(self) -> bool:
        return self.status == 202

    @property
    def reason_code(self) -> str | None:
        for part in (self.body, self.body.get("action") or {}, self.body.get("delegation") or {}):
            if part.get("reason_code") and part.get("decision") != "allow":
                return part["reason_code"]
        return self.body.get("reason_code")

    @property
    def approval_id(self) -> str | None:
        return self.body.get("approval_id") or (self.body.get("delegation") or {}).get("approval_id") or (self.body.get("action") or {}).get("approval_id")

    @property
    def execution(self) -> dict[str, Any] | None:
        return self.body.get("execution") or (self.body.get("action") or {}).get("execution")


class HarnessClient:
    def __init__(self, base_url: str, token: str | Callable[[], str], *, timeout: float = 30.0) -> None:
        """`token` is a short-lived harness token, or a callable returning the current one."""
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"HarnessClient({self.base_url!r}, token=<redacted>)"

    def act(self, action: str, arguments: dict[str, Any] | None = None) -> Outcome:
        return self._call("POST", "/v1/actions", {"action": action, "arguments": arguments or {}})

    def send_message(self, to: str, body: Any) -> Outcome:
        return self._call("POST", "/v1/messages", {"to": to, "body": body})

    def receive(self) -> list[dict[str, Any]]:
        return self._call("GET", "/v1/messages").body.get("messages", [])

    def delegate(self, to: str, action: str, arguments: dict[str, Any] | None = None) -> Outcome:
        return self._call("POST", "/v1/delegations", {"to": to, "action": action, "arguments": arguments or {}})

    def approval_status(self, approval_id: str) -> Outcome:
        return self._call("GET", f"/v1/approvals/{approval_id}")

    # approver-side
    def pending_approvals(self) -> list[dict[str, Any]]:
        return self._call("GET", "/v1/approvals").body.get("approvals", [])

    def decide_approval(self, approval_id: str, approve: bool, note: str = "") -> Outcome:
        return self._call("POST", f"/v1/approvals/{approval_id}", {"verdict": "approve" if approve else "reject", "note": note})

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Outcome:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {self._token() if callable(self._token) else self._token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return Outcome(resp.status, json.loads(resp.read() or b"{}"))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return Outcome(exc.code, json.loads(raw or b"{}"))
            except json.JSONDecodeError:
                return Outcome(exc.code, {"error": raw.decode(errors="replace")})
