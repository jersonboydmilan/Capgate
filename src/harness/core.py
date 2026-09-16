"""Harness: the developer-facing facade.

    harness = Harness(contract, tools={"web.search": search})
    result = harness.authorize(agent="researcher", action="web.search", arguments={...})
    if result.allowed:
        harness.execute(result)

The agent proposes. The harness authorizes. The executor acts.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping

from .audit import AuditLog
from .contract import TaskContract
from .decision import Decision, DecisionType, PolicyEvaluation, ReasonCode
from .executor import ExecutionGrant, ExecutionRefused, ExecutionResult, Executor, GrantSigner, Tool
from .interceptor import Interceptor
from .policy import Usage, evaluate
from .request import DELEGATE_ACTION, MESSAGE_ACTION, ActionRequest, DelegationRequest, MalformedRequest, MessageRequest
from .state import MemoryStateStore, StateStore
from .timeutil import Clock, utc_now


class Mode(str, Enum):
    ENFORCE = "enforce"
    SIMULATE = "simulate"


class ApprovalError(PermissionError):
    pass


@dataclass(frozen=True)
class AuthorizationResult:
    decision: Decision
    grant: ExecutionGrant | None = None
    approval_id: str | None = None

    @property
    def request(self) -> ActionRequest:
        return self.decision.request

    @property
    def decision_id(self) -> str:
        return self.decision.decision_id

    @property
    def reason_code(self) -> ReasonCode:
        return self.decision.reason_code

    @property
    def allowed(self) -> bool:
        return self.decision.allowed

    @property
    def denied(self) -> bool:
        return self.decision.denied

    @property
    def escalated(self) -> bool:
        return self.decision.escalated

    def to_dict(self) -> dict[str, Any]:
        return {**self.decision.to_dict(), "approval_id": self.approval_id}


@dataclass(frozen=True)
class DelegationResult:
    """Two independent decisions: may the sender ask, and may the recipient act."""

    delegation: AuthorizationResult
    action: AuthorizationResult | None = None

    @property
    def final(self) -> AuthorizationResult:
        return self.action if self.action is not None else self.delegation

    @property
    def allowed(self) -> bool:
        return self.delegation.allowed and self.action is not None and self.action.allowed

    @property
    def decision(self) -> Decision:
        return self.final.decision

    @property
    def reason_code(self) -> ReasonCode:
        return self.final.reason_code

    @property
    def blocked_at(self) -> str | None:
        if self.allowed:
            return None
        return "recipient" if self.action is not None else "sender"


@dataclass(frozen=True)
class Message:
    """A delivered message. It carries data, never authority."""

    message_id: str
    sender: str
    recipient: str
    body: Any
    decision_id: str


@dataclass(frozen=True)
class PendingApproval:
    approval_id: str
    decision: Decision
    usage: Usage
    created_at: datetime

    def to_record(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "status": "pending",
            "decision": self.decision.to_record(),
            "usage": {"contract_steps": self.usage.contract_steps, "action_calls": self.usage.action_calls},
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "PendingApproval":
        return cls(
            record["approval_id"],
            Decision.from_record(record["decision"]),
            Usage(**record["usage"]),
            datetime.fromisoformat(record["created_at"]),
        )


class Harness:
    def __init__(
        self,
        contracts: TaskContract | Iterable[TaskContract],
        *,
        tools: Mapping[str, Tool] | None = None,
        audit: AuditLog | None = None,
        mode: Mode | str = Mode.ENFORCE,
        clock: Clock = utc_now,
        signing_key: bytes | None = None,
        grant_ttl_seconds: float = 60.0,
        state: StateStore | None = None,
    ) -> None:
        """`state` persists budgets, used grants, approvals and messages (see harness.state).

        Grants survive a restart only if `signing_key` is also stable.
        """
        if isinstance(contracts, TaskContract):
            contracts = [contracts]
        self.mode = Mode(mode)
        self.audit = audit if audit is not None else AuditLog()
        self._clock = clock
        self.state = state if state is not None else MemoryStateStore()
        self._interceptor = Interceptor(contracts, self.audit, clock, simulate=self.mode is Mode.SIMULATE, state=self.state)
        self._grant_ttl = grant_ttl_seconds
        self._signer = GrantSigner(signing_key)
        self._lock = threading.RLock()

        tool_map = dict(tools or {})
        reserved = {MESSAGE_ACTION, DELEGATE_ACTION} & set(tool_map)
        if reserved:
            raise ValueError(f"{sorted(reserved)} are handled by the harness and cannot be registered as tools")
        tool_map[MESSAGE_ACTION] = self._deliver
        self._executor = Executor(self._signer, tool_map, self.audit, clock=lambda: self._clock().timestamp(), state=self.state)

    # -- introspection ---------------------------------------------------

    @property
    def contracts(self) -> Mapping[str, TaskContract]:
        return dict(self._interceptor.contracts)

    def contract_for(self, agent_id: str) -> TaskContract | None:
        contract_id = self._interceptor.bindings.get(agent_id)
        return self._interceptor.contracts.get(contract_id) if contract_id else None

    def is_agent(self, agent_id: str) -> bool:
        return agent_id in self._interceptor.bindings

    # -- tool calls ------------------------------------------------------

    def authorize(
        self,
        agent: str,
        action: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        contract_id: str | None = None,
    ) -> AuthorizationResult:
        try:
            request = ActionRequest(agent_id=agent, action=action, arguments=arguments or {}, contract_id=contract_id)
        except MalformedRequest as exc:
            return AuthorizationResult(self._interceptor.reject_before_policy(agent, action, ReasonCode.MALFORMED_REQUEST, str(exc)))
        return self.authorize_request(request)

    def authorize_request(self, request: ActionRequest, *, delegated_by: str | None = None, parent_decision_id: str | None = None) -> AuthorizationResult:
        decision, usage = self._interceptor.decide(request, delegated_by=delegated_by, parent_decision_id=parent_decision_id)
        return self._result_for(decision, usage)

    def execute(self, result: AuthorizationResult) -> ExecutionResult:
        """Execute an authorized action. Refuses anything without a valid grant."""
        request = result.request
        if self.mode is Mode.SIMULATE or result.grant is None:
            reason = "SIMULATION_MODE" if self.mode is Mode.SIMULATE else "NO_GRANT"
            detail = "no external actions are executed in simulation" if self.mode is Mode.SIMULATE else f"decision was {result.decision.decision.value}"
            self.audit.record(
                "execution_refused",
                decision_id=result.decision_id,
                agent_id=request.agent_id,
                action=request.action,
                arguments_hash=request.arguments_hash,
                reason_code=reason,
                detail=detail,
                outcome="refused",
            )
            raise ExecutionRefused(reason, detail)
        return self._executor.execute(result.grant, request)

    def execute_grant(self, grant: ExecutionGrant, request: ActionRequest) -> ExecutionResult:
        """Lower-level entry used by the HTTP server; the executor verifies everything."""
        return self._executor.execute(grant, request)

    def run(self, agent: str, action: str, arguments: Mapping[str, Any] | None = None) -> tuple[AuthorizationResult, ExecutionResult | None]:
        result = self.authorize(agent, action, arguments)
        if result.allowed and self.mode is Mode.ENFORCE:
            return result, self.execute(result)
        return result, None

    # -- messages --------------------------------------------------------

    def send_message(self, sender: str, recipient: str, body: Any, *, contract_id: str | None = None) -> AuthorizationResult:
        try:
            request = MessageRequest(sender, recipient, body, contract_id).to_action_request()
        except MalformedRequest as exc:
            return AuthorizationResult(self._interceptor.reject_before_policy(sender, MESSAGE_ACTION, ReasonCode.MALFORMED_REQUEST, str(exc)))
        result = self.authorize_request(request)
        if result.allowed and self.mode is Mode.ENFORCE:
            self.execute(result)
        return result

    def receive(self, agent: str) -> list[Message]:
        return [Message(**m) for m in self.state.drain_messages(agent)]

    def _deliver(self, arguments: dict[str, Any], request: ActionRequest, decision_id: str) -> dict[str, Any]:
        message = Message(str(uuid.uuid4()), request.agent_id, arguments["to"], arguments.get("body"), decision_id)
        self.state.push_message(message.recipient, message.__dict__)
        return {"message_id": message.message_id, "delivered_to": message.recipient}

    _deliver.__harness_context__ = True  # type: ignore[attr-defined]

    # -- delegation ------------------------------------------------------

    def delegate(
        self,
        sender: str,
        recipient: str,
        action: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        contract_id: str | None = None,
    ) -> DelegationResult:
        """Agent `sender` asks agent `recipient` to perform `action`.

        Stage 1 checks the sender's own right to ask (agent.delegate, with
        allowed_targets and allowed_actions). Stage 2 evaluates the action as
        the recipient's proposal under the recipient's contract alone. The
        sender's authority is never consulted in stage 2 — the policy engine
        has no input through which it could be.
        """
        try:
            req = DelegationRequest(sender, recipient, action, dict(arguments or {}), contract_id)
            stage1 = req.delegation_request()
        except MalformedRequest as exc:
            return DelegationResult(AuthorizationResult(self._interceptor.reject_before_policy(sender, DELEGATE_ACTION, ReasonCode.MALFORMED_REQUEST, str(exc))))
        first = self.authorize_request(stage1)
        if not first.allowed:
            return DelegationResult(first)
        return DelegationResult(first, self._delegated_stage(req, first.decision))

    def _delegated_stage(self, req: DelegationRequest, parent: Decision) -> AuthorizationResult:
        return self.authorize_request(req.delegated_action(), delegated_by=req.sender, parent_decision_id=parent.decision_id)

    # -- escalation ------------------------------------------------------

    def pending_approvals(self) -> list[PendingApproval]:
        return [PendingApproval.from_record(r) for r in self.state.pending_approvals()]

    def approval_record(self, approval_id: str) -> dict[str, Any] | None:
        """Persisted status of an escalation: pending or decided (with verdict and resulting decision)."""
        return self.state.get_approval(approval_id)

    def annotate_approval(self, approval_id: str, **fields: Any) -> None:
        with self.state.transaction():
            record = self.state.get_approval(approval_id)
            if record is not None:
                record.update(fields)
                self.state.put_approval(approval_id, record)

    def approve(self, approval_id: str, approver: str, note: str = "") -> AuthorizationResult | DelegationResult:
        pending = self._take_approval(approval_id, approver, "approve")
        request = pending.decision.request
        with self._lock:
            evaluation = evaluate(request, self._interceptor.contracts, self._interceptor.bindings, pending.usage, self._clock())
            if evaluation.decision is DecisionType.ESCALATE:
                evaluation = PolicyEvaluation(
                    DecisionType.ALLOW, ReasonCode.APPROVED_BY_HUMAN, f"approved by {approver}" + (f": {note}" if note else ""),
                    capability=evaluation.capability, rule="approval:granted",
                )
            decision = self._interceptor.record(
                request, evaluation,
                delegated_by=pending.decision.delegated_by,
                parent_decision_id=pending.decision.decision_id,
                approved_by=approver if evaluation.decision is DecisionType.ALLOW else None,
            )
        self.audit.record(
            "approval",
            approval_id=approval_id,
            decision_id=pending.decision.decision_id,
            resulting_decision_id=decision.decision_id,
            agent_id=request.agent_id,
            action=request.action,
            approver=approver,
            verdict="granted" if decision.allowed else "superseded",
            note=note,
        )
        self.annotate_approval(approval_id, verdict="granted" if decision.allowed else "superseded", resulting_decision_id=decision.decision_id)
        result = self._result_for(decision, pending.usage)
        if request.action == DELEGATE_ACTION and result.allowed:
            args = request.arguments_copy()
            req = DelegationRequest(request.agent_id, args["to"], args["action"], args.get("arguments") or {})
            return DelegationResult(result, self._delegated_stage(req, decision))
        return result

    def reject(self, approval_id: str, approver: str, note: str = "") -> AuthorizationResult:
        pending = self._take_approval(approval_id, approver, "reject")
        request = pending.decision.request
        evaluation = PolicyEvaluation(DecisionType.DENY, ReasonCode.APPROVAL_REJECTED, f"rejected by {approver}" + (f": {note}" if note else ""), capability=request.action, rule="approval:rejected")
        decision = self._interceptor.record(request, evaluation, delegated_by=pending.decision.delegated_by, parent_decision_id=pending.decision.decision_id)
        self.annotate_approval(approval_id, verdict="rejected", resulting_decision_id=decision.decision_id)
        self.audit.record(
            "approval",
            approval_id=approval_id,
            decision_id=pending.decision.decision_id,
            resulting_decision_id=decision.decision_id,
            agent_id=request.agent_id,
            action=request.action,
            approver=approver,
            verdict="rejected",
            note=note,
        )
        return AuthorizationResult(decision)

    def _take_approval(self, approval_id: str, approver: str, verb: str) -> PendingApproval:
        with self._lock, self.state.transaction():
            record = self.state.get_approval(approval_id)
            pending = PendingApproval.from_record(record) if record and record["status"] == "pending" else None
            if pending is None:
                self.audit.record("approval_refused", approval_id=approval_id, approver=approver, reason_code="UNKNOWN_APPROVAL", detail=f"{verb}: no pending approval")
                raise ApprovalError(f"no pending approval {approval_id!r}")
            contract = self._interceptor.contracts.get(pending.decision.contract_id or "")
            if self.is_agent(approver) or contract is None or approver not in contract.approvers:
                self.audit.record(
                    "approval_refused",
                    approval_id=approval_id,
                    decision_id=pending.decision.decision_id,
                    approver=approver,
                    reason_code="UNAUTHORIZED_APPROVER",
                    detail=f"{approver!r} is not an approver for {pending.decision.contract_id!r}",
                )
                raise ApprovalError(f"{approver!r} may not {verb} requests under {pending.decision.contract_id!r}")
            record.update(status="decided", verb=verb, approver=approver)
            self.state.put_approval(approval_id, record)  # single use: a decided approval can never be taken again
            return pending

    # -- internals -------------------------------------------------------

    def _result_for(self, decision: Decision, usage: Usage) -> AuthorizationResult:
        if decision.escalated:
            approval_id = str(uuid.uuid4())
            self.state.put_approval(approval_id, PendingApproval(approval_id, decision, usage, self._clock()).to_record())
            return AuthorizationResult(decision, approval_id=approval_id)
        if decision.allowed and self.mode is Mode.ENFORCE:
            return AuthorizationResult(decision, grant=self._mint_grant(decision))
        return AuthorizationResult(decision)

    def _mint_grant(self, decision: Decision) -> ExecutionGrant:
        request = decision.request
        payload = {
            "decision_id": decision.decision_id,
            "agent_id": request.agent_id,
            "contract_id": decision.contract_id,
            "action": request.action,
            "arguments_hash": request.arguments_hash,
            "expires_at": self._clock().timestamp() + self._grant_ttl,
        }
        return ExecutionGrant(**payload, signature=self._signer.sign(payload))
