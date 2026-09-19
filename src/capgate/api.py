"""Transport-independent HTTP API for the harness boundary.

`HarnessAPI.dispatch` takes an already-framed request (method, path, headers,
body bytes, client address) and returns a `Response`. HTTP framing — parsing,
timeouts, connection handling — belongs to the transport: `harness.asgi` for
production (uvicorn), `harness.server` for development and tests. Every
transport goes through this one function, so they cannot disagree about
authentication, limits or policy.

    POST /v1/actions             {action, arguments}         -> 200 executed | 403 denied | 202 escalated
    POST /v1/messages            {to, body}                  -> 200 delivered | 403 | 202
    GET  /v1/messages                                        -> messages delivered to the caller
    POST /v1/delegations         {to, action, arguments}     -> 200 | 403 | 202
    GET  /v1/approvals/<id>                                  -> status of the caller's escalation
    GET  /v1/approvals           (approver token)            -> pending approvals the caller may decide
    POST /v1/approvals/<id>      (approver token) {verdict: approve|reject, note}
    POST /mcp                    MCP Streamable HTTP (JSON-RPC), agent token
    GET  /v1/health
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .core import ApprovalError, AuthorizationResult, DelegationResult, Harness, Mode
from .decision import ReasonCode
from .executor import ExecutionRefused
from .identity import TokenAuthority, TokenError
from .ratelimit import RateLimitConfig, RateLimiter
from .workload import WorkloadIdentity

MAX_BODY = 1_000_000
_APPROVAL_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


@dataclass
class Response:
    status: int
    body: Any
    headers: dict[str, str] = field(default_factory=dict)
    close: bool = False
    empty: bool = False  # e.g. 202 for a JSON-RPC notification: no body at all

    def encode(self) -> bytes:
        return b"" if self.empty else json.dumps(self.body, default=str, separators=(",", ":")).encode()


class HarnessAPI:
    def __init__(self, harness: Harness, authority: TokenAuthority, *, rate_limit: RateLimitConfig | None = None) -> None:
        if harness.mode is not Mode.ENFORCE:
            raise ValueError("the HTTP API runs in enforce mode; use `capgate simulate` for dry runs")
        if authority.state is None:
            authority.state = harness.state  # revocations live with the rest of the authority state
        self.harness = harness
        self.authority = authority
        self.limiter = RateLimiter(rate_limit, store=harness.state)
        self._approvers = {a for c in harness.contracts.values() for a in c.approvers}
        self._extra_routes: dict[tuple[str, str], Callable[..., Response]] = {}

    def add_route(self, method: str, path: str, handler: Callable[[str, bytes, dict[str, str]], Response]) -> None:
        """Mount an extension endpoint (e.g. MCP). Handler receives (agent_id, raw_body, headers) after auth and limits."""
        self._extra_routes[(method, path)] = handler

    # -- entry point -----------------------------------------------------------

    def dispatch(self, method: str, target: str, headers: Mapping[str, str], body: bytes | None, client: str,
                 workload: WorkloadIdentity | None = None) -> Response:
        path = target.split("?", 1)[0]
        try:
            return self._dispatch(method.upper(), path, {k.lower(): v for k, v in headers.items()}, body, client, workload)
        except Exception as exc:  # fail closed, never leak internals
            self.harness.audit.record("server_error", path=path[:200], error=type(exc).__name__)
            return Response(500, {"error": "internal error; nothing was executed unless an execution record exists"}, close=True)

    def _dispatch(self, method: str, path: str, headers: dict[str, str], body: bytes | None, client: str,
                  workload: WorkloadIdentity | None = None) -> Response:
        if path == "/v1/health":
            return Response(200, {"ok": True}) if method in ("GET", "HEAD") else Response(405, {"error": "method not allowed"})
        if method not in ("GET", "POST"):
            return Response(405, {"error": "method not allowed"}, {"Allow": "GET, POST"})

        gate = self._gate(path, method, headers.get("authorization"), client, workload)
        if isinstance(gate, Response):
            return gate
        agent, approver = gate

        extra = self._extra_routes.get((method, path))
        if extra is not None:
            if not agent:
                return Response(404, {"error": "not found"})
            return extra(agent, body or b"", headers)

        if method == "GET":
            if path == "/v1/messages" and agent:
                return Response(200, {"messages": [m.__dict__ for m in self.harness.receive(agent)]})
            if path == "/v1/approvals" and approver:
                return Response(200, {"approvals": self.list_approvals(approver)})
            if path.startswith("/v1/approvals/") and agent:
                approval_id = path[len("/v1/approvals/"):]
                if not _APPROVAL_ID.match(approval_id):
                    return Response(404, {"error": "unknown approval"})
                return Response(*self.approval_status(agent, approval_id))
            return Response(404, {"error": "not found"})

        data = _json_object(body)
        if data is None:
            return Response(400, {"error": "request body must be a JSON object under 1MB"}, close=True)
        if path == "/v1/actions" and agent:
            return Response(*self.handle_action(agent, data))
        if path == "/v1/messages" and agent:
            return Response(*self.handle_message(agent, data))
        if path == "/v1/delegations" and agent:
            return Response(*self.handle_delegation(agent, data))
        if path.startswith("/v1/approvals/") and approver:
            approval_id = path[len("/v1/approvals/"):]
            if not _APPROVAL_ID.match(approval_id):
                return Response(404, {"error": "unknown approval"})
            return Response(*self.handle_approval(approver, approval_id, data))
        return Response(404, {"error": "not found"})

    # -- identity and limits ----------------------------------------------------

    def identify(self, header: str | None, workload: WorkloadIdentity | None = None) -> tuple[str | None, str | None, str | None]:
        """Return (agent_id, approver_id, failure_reason) for an Authorization header."""
        if not header or not header.startswith("Bearer "):
            return None, None, "TOKEN_MISSING"
        try:
            claims = self.authority.verify(header[len("Bearer "):].strip(), workload=workload)
        except TokenError as exc:
            return None, None, exc.reason
        if claims.role == "agent" and self.harness.is_agent(claims.sub):
            return claims.sub, None, None
        if claims.role == "approver" and claims.sub in self._approvers and not self.harness.is_agent(claims.sub):
            return None, claims.sub, None
        return None, None, "TOKEN_UNKNOWN_PRINCIPAL"

    def _gate(self, path: str, method: str, authorization: str | None, client: str,
              workload: WorkloadIdentity | None = None) -> tuple[str | None, str | None] | Response:
        """Client limit → authentication (with workload binding) → principal limit."""
        allowed, retry = self.limiter.client(client)
        if not allowed:
            return self._limited(retry, "client", client, client, path)
        agent, approver, failure = self.identify(authorization, workload)
        if failure is not None:
            record, suppressed = self.limiter.audit_auth_failure(client)
            if record:
                self.harness.audit.record(
                    "authentication_failed", path=path[:200], method=method,
                    reason_code=ReasonCode.UNAUTHENTICATED.value, credential_error=failure, client=client,
                    suppressed_since_last=suppressed,
                )
            return Response(401, {"error": "unauthenticated"}, {"WWW-Authenticate": "Bearer"}, close=True)
        principal = agent or approver
        allowed, retry = self.limiter.principal(principal)
        if not allowed:
            return self._limited(retry, "principal", principal, client, path)
        return agent, approver

    def _limited(self, retry: float, scope: str, key: str, client: str, path: str) -> Response:
        record, suppressed = self.limiter.audit_auth_failure(f"{scope}:{key}")
        if record:
            self.harness.audit.record(
                "rate_limited", scope=scope, principal=key if scope == "principal" else None,
                client=client, path=path[:200], suppressed_since_last=suppressed,
            )
        return Response(429, {"error": "rate limited", "retry_after_seconds": round(retry, 2)}, {"Retry-After": str(max(1, math.ceil(retry)))}, close=True)

    # -- handlers ------------------------------------------------------------------

    def handle_action(self, agent: str, body: Mapping[str, Any]) -> tuple[int, dict]:
        if (mismatch := self._identity_mismatch(agent, body, body.get("action", "invalid"))) is not None:
            return mismatch
        result = self.harness.authorize(agent, body.get("action"), _arguments(body), contract_id=body.get("contract_id"))
        return self.respond(result)

    def handle_message(self, agent: str, body: Mapping[str, Any]) -> tuple[int, dict]:
        if (mismatch := self._identity_mismatch(agent, body, "agent.message")) is not None:
            return mismatch
        result = self.harness.send_message(agent, body.get("to"), body.get("body"), contract_id=body.get("contract_id"))
        payload = result.to_dict()
        if result.escalated:
            return 202, payload
        return (200 if result.allowed else 403), payload

    def handle_delegation(self, agent: str, body: Mapping[str, Any]) -> tuple[int, dict]:
        if (mismatch := self._identity_mismatch(agent, body, "agent.delegate")) is not None:
            return mismatch
        delegation = self.harness.delegate(agent, body.get("to"), body.get("action"), _arguments(body), contract_id=body.get("contract_id"))
        return self.respond_delegation(delegation)

    def handle_approval(self, approver: str, approval_id: str, body: Mapping[str, Any]) -> tuple[int, dict]:
        verdict = body.get("verdict")
        if verdict not in ("approve", "reject"):
            return 400, {"error": "verdict must be 'approve' or 'reject'"}
        note = body.get("note")
        note = note if isinstance(note, str) else ""
        try:
            if verdict == "approve":
                outcome = self.harness.approve(approval_id, approver, note[:2000])
            else:
                outcome = self.harness.reject(approval_id, approver, note[:2000])
        except ApprovalError as exc:
            return 403, {"error": str(exc)}
        status, payload = self.respond_delegation(outcome) if isinstance(outcome, DelegationResult) else self.respond(outcome)
        self.harness.annotate_approval(approval_id, result=payload)
        return status, payload

    def list_approvals(self, approver: str) -> list[dict]:
        out = []
        for pending in self.harness.pending_approvals():
            contract = self.harness.contracts.get(pending.decision.contract_id or "")
            if contract and approver in contract.approvers:
                out.append({"approval_id": pending.approval_id, **pending.decision.to_dict(), "arguments": pending.decision.request.arguments_copy()})
        return out

    def approval_status(self, agent: str, approval_id: str) -> tuple[int, dict]:
        record = self.harness.approval_record(approval_id)
        if not record or record["decision"]["request"]["agent_id"] != agent:
            return 404, {"error": "unknown approval"}
        return 200, {
            "approval_id": approval_id,
            "status": record["status"],
            "verdict": record.get("verdict"),
            "resulting_decision_id": record.get("resulting_decision_id"),
            "result": record.get("result"),
        }

    # -- shared response shaping ------------------------------------------------------

    def _identity_mismatch(self, agent: str, body: Mapping[str, Any], action: Any) -> tuple[int, dict] | None:
        claimed = body.get("agent_id")
        if claimed is None or claimed == agent:
            return None
        decision = self.harness._interceptor.reject_before_policy(
            agent, action if isinstance(action, str) else "invalid", ReasonCode.IDENTITY_MISMATCH,
            f"authenticated as {agent!r} but request claimed {str(claimed)[:100]!r}",
        )
        return 403, decision.to_dict()

    def respond(self, result: AuthorizationResult) -> tuple[int, dict]:
        payload = result.to_dict()
        if result.escalated:
            return 202, payload
        if not result.allowed:
            return 403, payload
        try:
            execution = self.harness.execute(result)
        except ExecutionRefused as refusal:
            return 502, {**payload, "execution": {"status": "refused", "reason": refusal.reason}}
        return 200, {**payload, "execution": execution.to_dict()}

    def respond_delegation(self, delegation: DelegationResult) -> tuple[int, dict]:
        first_payload = delegation.delegation.to_dict()
        if delegation.action is None:
            if delegation.delegation.escalated:
                return 202, {"delegation": first_payload, "action": None}
            return 403, {"delegation": first_payload, "action": None, "blocked_at": "sender"}
        status, action_payload = self.respond(delegation.action)
        body = {"delegation": first_payload, "action": action_payload}
        if status == 403:
            body["blocked_at"] = "recipient"
        return status, body


def _json_object(body: bytes | None) -> dict | None:
    if body is None or len(body) > MAX_BODY:
        return None
    try:
        data = json.loads(body or b"{}", parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")  # NaN/Infinity cannot be audited canonically


def _arguments(body: Mapping[str, Any]) -> Any:
    args = body.get("arguments")
    return {} if args is None else args

