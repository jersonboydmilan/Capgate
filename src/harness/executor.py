"""The executor: the only component that holds tool credentials.

It performs an action only when presented with an ExecutionGrant that
  * was signed by the harness that made the `allow` decision,
  * names the same agent, contract, action and exact argument hash,
  * has not expired, and
  * has not been used before.

Anything else is refused before a tool is touched. The harness only ever
mints a grant for an `allow` decision, so a denied or escalated request has
no path to a tool.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Mapping, Protocol

from .audit import AuditLog
from .request import ActionRequest, canonical_json


class ExecutionRefused(PermissionError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class Tool(Protocol):
    def __call__(self, arguments: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class ExecutionGrant:
    decision_id: str
    agent_id: str
    contract_id: str
    action: str
    arguments_hash: str
    expires_at: float
    signature: str

    def payload(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "contract_id": self.contract_id,
            "action": self.action,
            "arguments_hash": self.arguments_hash,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionGrant":
        try:
            return cls(
                decision_id=str(data["decision_id"]),
                agent_id=str(data["agent_id"]),
                contract_id=str(data["contract_id"]),
                action=str(data["action"]),
                arguments_hash=str(data["arguments_hash"]),
                expires_at=float(data["expires_at"]),
                signature=str(data["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ExecutionRefused("MALFORMED_GRANT", str(exc)) from None


class GrantSigner:
    """HMAC-SHA256 signer. The key never leaves the harness process."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)

    def sign(self, payload: Mapping[str, Any]) -> str:
        return hmac.new(self._key, canonical_json(dict(payload)).encode(), sha256).hexdigest()

    def verify(self, grant: ExecutionGrant) -> bool:
        return hmac.compare_digest(self.sign(grant.payload()), grant.signature)


@dataclass(frozen=True)
class ExecutionResult:
    decision_id: str
    action: str
    status: str  # "succeeded" | "failed"
    output: Any = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "succeeded"

    def to_dict(self) -> dict[str, Any]:
        return {"decision_id": self.decision_id, "action": self.action, "status": self.status, "output": self.output, "error": self.error}


class Executor:
    def __init__(
        self,
        signer: GrantSigner,
        tools: Mapping[str, Tool] | None,
        audit: AuditLog,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._signer = signer
        self._tools = dict(tools or {})
        self._audit = audit
        self._clock = clock
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def has_tool(self, action: str) -> bool:
        return action in self._tools

    def execute(self, grant: ExecutionGrant, request: ActionRequest) -> ExecutionResult:
        try:
            tool = self._check(grant, request)
        except ExecutionRefused as refusal:
            self._audit.record(
                "execution_refused",
                decision_id=grant.decision_id,
                agent_id=request.agent_id,
                action=request.action,
                arguments_hash=request.arguments_hash,
                reason_code=refusal.reason,
                detail=refusal.detail,
                outcome="refused",
            )
            raise

        try:
            if getattr(tool, "__harness_context__", False):
                output = tool(request.arguments_copy(), request, grant.decision_id)
            else:
                output = tool(request.arguments_copy())
            result = ExecutionResult(grant.decision_id, request.action, "succeeded", output=output)
        except Exception as exc:  # tool failures are outcomes, not authorization events
            result = ExecutionResult(grant.decision_id, request.action, "failed", error=f"{type(exc).__name__}: {exc}")
        self._audit.record(
            "execution",
            decision_id=grant.decision_id,
            agent_id=request.agent_id,
            contract_id=grant.contract_id,
            action=request.action,
            arguments_hash=request.arguments_hash,
            outcome=result.status,
            error=result.error,
        )
        return result

    def _check(self, grant: ExecutionGrant, request: ActionRequest) -> Tool:
        if not self._signer.verify(grant):
            raise ExecutionRefused("INVALID_GRANT_SIGNATURE", "grant was not issued by this harness")
        if grant.agent_id != request.agent_id or grant.action != request.action:
            raise ExecutionRefused("GRANT_REQUEST_MISMATCH", "grant does not cover this agent/action")
        if grant.arguments_hash != request.arguments_hash:
            raise ExecutionRefused("GRANT_ARGUMENTS_MISMATCH", "arguments differ from those authorized")
        if self._clock() >= grant.expires_at:
            raise ExecutionRefused("GRANT_EXPIRED")
        tool = self._tools.get(request.action)
        if tool is None:
            raise ExecutionRefused("NO_TOOL_REGISTERED", f"no executor tool for {request.action!r}")
        with self._lock:
            if grant.decision_id in self._used:
                raise ExecutionRefused("GRANT_ALREADY_USED", "grants are single-use")
            self._used.add(grant.decision_id)
        return tool
