"""HTTP API: the harness as a network boundary.

Principals authenticate with short-lived signed bearer tokens (see
harness.identity); the identity used for policy is derived from the verified
token, never from the request body. Agents never receive
execution grants or tool credentials — the server authorizes and executes in
one step and returns only the outcome.

    POST /v1/actions             {action, arguments}         -> 200 executed | 403 denied | 202 escalated
    POST /v1/messages            {to, body}                  -> 200 delivered | 403 | 202
    GET  /v1/messages                                        -> messages delivered to the caller
    POST /v1/delegations         {to, action, arguments}     -> 200 | 403 | 202
    GET  /v1/approvals/<id>                                  -> status of the caller's escalation
    GET  /v1/approvals           (approver token)            -> pending approvals the caller may decide
    POST /v1/approvals/<id>      (approver token) {verdict: approve|reject, note}
    GET  /v1/health
"""

from __future__ import annotations

import json
import math
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

from .core import ApprovalError, AuthorizationResult, DelegationResult, Harness, Mode
from .decision import ReasonCode
from .executor import ExecutionRefused
from .identity import TokenAuthority, TokenError
from .ratelimit import RateLimitConfig, RateLimiter

MAX_BODY = 1_000_000
REQUEST_TIMEOUT_SECONDS = 10.0


class HarnessServer:
    def __init__(
        self,
        harness: Harness,
        authority: TokenAuthority,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        rate_limit: RateLimitConfig | None = None,
    ) -> None:
        if harness.mode is not Mode.ENFORCE:
            raise ValueError("the HTTP server runs in enforce mode; use `harness simulate` for dry runs")
        if authority.state is None:
            authority.state = harness.state  # revocations live with the rest of the authority state
        self.harness = harness
        self.authority = authority
        self.limiter = RateLimiter(rate_limit)
        self._approvers = {a for c in harness.contracts.values() for a in c.approvers}
        self.server = ThreadingHTTPServer((host, port), _make_handler(self))
        self.url = f"http://{host}:{self.server.server_address[1]}"
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "HarnessServer":
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # -- identity ----------------------------------------------------------

    def identify(self, header: str | None) -> tuple[str | None, str | None, str | None]:
        """Return (agent_id, approver_id, failure_reason) for an Authorization header."""
        if not header or not header.startswith("Bearer "):
            return None, None, "TOKEN_MISSING"
        try:
            claims = self.authority.verify(header[len("Bearer "):].strip())
        except TokenError as exc:
            return None, None, exc.reason
        if claims.role == "agent" and self.harness.is_agent(claims.sub):
            return claims.sub, None, None
        if claims.role == "approver" and claims.sub in self._approvers and not self.harness.is_agent(claims.sub):
            return None, claims.sub, None
        return None, None, "TOKEN_UNKNOWN_PRINCIPAL"

    # -- handlers ------------------------------------------------------------

    def handle_action(self, agent: str, body: Mapping[str, Any]) -> tuple[int, dict]:
        if (mismatch := self._identity_mismatch(agent, body, body.get("action", "invalid"))) is not None:
            return mismatch
        result = self.harness.authorize(agent, body.get("action"), body.get("arguments") or {}, contract_id=body.get("contract_id"))
        return self._respond(result)

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
        delegation = self.harness.delegate(agent, body.get("to"), body.get("action"), body.get("arguments") or {}, contract_id=body.get("contract_id"))
        return self._respond_delegation(delegation)

    def handle_approval(self, approver: str, approval_id: str, body: Mapping[str, Any]) -> tuple[int, dict]:
        verdict = body.get("verdict")
        if verdict not in ("approve", "reject"):
            return 400, {"error": "verdict must be 'approve' or 'reject'"}
        try:
            if verdict == "approve":
                outcome = self.harness.approve(approval_id, approver, str(body.get("note") or ""))
            else:
                outcome = self.harness.reject(approval_id, approver, str(body.get("note") or ""))
        except ApprovalError as exc:
            return 403, {"error": str(exc)}
        if isinstance(outcome, DelegationResult):
            status, payload = self._respond_delegation(outcome)
        else:
            status, payload = self._respond(outcome)
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

    # -- helpers ---------------------------------------------------------------

    def _identity_mismatch(self, agent: str, body: Mapping[str, Any], action: Any) -> tuple[int, dict] | None:
        claimed = body.get("agent_id")
        if claimed is None or claimed == agent:
            return None
        decision = self.harness._interceptor.reject_before_policy(
            agent, action if isinstance(action, str) else "invalid", ReasonCode.IDENTITY_MISMATCH,
            f"authenticated as {agent!r} but request claimed {claimed!r}",
        )
        return 403, decision.to_dict()

    def _respond(self, result: AuthorizationResult) -> tuple[int, dict]:
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

    def _respond_delegation(self, delegation: DelegationResult) -> tuple[int, dict]:
        first_payload = delegation.delegation.to_dict()
        if delegation.action is None:
            if delegation.delegation.escalated:
                return 202, {"delegation": first_payload, "action": None}
            return 403, {"delegation": first_payload, "action": None, "blocked_at": "sender"}
        status, action_payload = self._respond(delegation.action)
        body = {"delegation": first_payload, "action": action_payload}
        if status == 403:
            body["blocked_at"] = "recipient"
        return status, body


def _make_handler(app: HarnessServer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "agent-harness"
        timeout = REQUEST_TIMEOUT_SECONDS  # per-socket-operation timeout: slow or stalled clients cannot hold a thread

        def log_message(self, *args):
            pass

        def _send(self, code: int, body: Any, headers: dict | None = None) -> None:
            data = json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> Mapping[str, Any] | None:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None or not raw_length.strip().isdigit():
                return None  # missing, negative or non-numeric: never "read until EOF"
            length = int(raw_length)
            if length > MAX_BODY:
                return None
            try:
                raw = self.rfile.read(length)
            except OSError:  # includes socket timeout
                return None
            if len(raw) != length:
                return None
            try:
                data = json.loads(raw or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            return data if isinstance(data, dict) else None

        def _limited(self, retry: float, scope: str, key: str) -> None:
            record, suppressed = app.limiter.audit_auth_failure(f"{scope}:{key}")
            if record:
                app.harness.audit.record(
                    "rate_limited", scope=scope, principal=key if scope == "principal" else None,
                    client=self.client_address[0], path=self.path, suppressed_since_last=suppressed,
                )
            self.close_connection = True
            self._send(429, {"error": "rate limited", "retry_after_seconds": round(retry, 2)}, {"Retry-After": str(max(1, math.ceil(retry)))})

        def _gate(self) -> tuple[str | None, str | None] | None:
            """Client limit → authentication → principal limit. Returns None if a response was already sent."""
            client = self.client_address[0]
            allowed, retry = app.limiter.client(client)
            if not allowed:
                self._limited(retry, "client", client)
                return None
            agent, approver, failure = app.identify(self.headers.get("Authorization"))
            if failure is not None:
                record, suppressed = app.limiter.audit_auth_failure(client)
                if record:
                    app.harness.audit.record(
                        "authentication_failed", path=self.path, method=self.command,
                        reason_code=ReasonCode.UNAUTHENTICATED.value, credential_error=failure, client=client,
                        suppressed_since_last=suppressed,
                    )
                self.close_connection = True
                self._send(401, {"error": "unauthenticated"})
                return None
            principal = agent or approver
            allowed, retry = app.limiter.principal(principal)
            if not allowed:
                self._limited(retry, "principal", principal)
                return None
            return agent, approver

        def do_GET(self) -> None:
            if self.path == "/v1/health":
                self._send(200, {"ok": True})
                return
            identity = self._gate()
            if identity is None:
                return
            agent, approver = identity
            if self.path == "/v1/messages" and agent:
                msgs = app.harness.receive(agent)
                self._send(200, {"messages": [m.__dict__ for m in msgs]})
            elif self.path == "/v1/approvals" and approver:
                self._send(200, {"approvals": app.list_approvals(approver)})
            elif self.path.startswith("/v1/approvals/") and agent:
                self._send(*app.approval_status(agent, self.path.rsplit("/", 1)[-1]))
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            identity = self._gate()
            if identity is None:
                return
            agent, approver = identity
            body = self._body()
            if body is None:
                self.close_connection = True
                self._send(400, {"error": "request body must be a JSON object under 1MB with a valid Content-Length"})
                return
            try:
                if self.path == "/v1/actions" and agent:
                    self._send(*app.handle_action(agent, body))
                elif self.path == "/v1/messages" and agent:
                    self._send(*app.handle_message(agent, body))
                elif self.path == "/v1/delegations" and agent:
                    self._send(*app.handle_delegation(agent, body))
                elif self.path.startswith("/v1/approvals/") and approver:
                    self._send(*app.handle_approval(approver, self.path.rsplit("/", 1)[-1], body))
                else:
                    self._send(404, {"error": "not found"})
            except Exception as exc:  # fail closed, never leak internals
                app.harness.audit.record("server_error", path=self.path, error=type(exc).__name__)
                self._send(500, {"error": "internal error; nothing was executed unless an execution record exists"})

    return Handler
