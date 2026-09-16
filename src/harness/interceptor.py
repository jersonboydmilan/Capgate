"""The interception point: every ActionRequest — tool call, message or
delegation — is decided here, counted, and audited before anything else
happens. There is no second code path.
"""

from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from typing import Iterable

from .audit import AuditLog
from .contract import TaskContract, build_bindings
from .decision import Decision, DecisionType, PolicyEvaluation, ReasonCode
from .policy import Usage, evaluate
from .request import ActionRequest
from .timeutil import Clock

_OUTCOME = {
    DecisionType.ALLOW: "authorized",
    DecisionType.DENY: "blocked",
    DecisionType.ESCALATE: "awaiting_approval",
}


class Interceptor:
    def __init__(self, contracts: Iterable[TaskContract], audit: AuditLog, clock: Clock, *, simulate: bool) -> None:
        self.contracts, self.bindings = build_bindings(contracts)
        self.audit = audit
        self.clock = clock
        self.simulate = simulate
        self._lock = threading.RLock()
        self._steps: dict[str, int] = defaultdict(int)
        self._calls: dict[tuple[str, str], int] = defaultdict(int)

    def usage_for(self, request: ActionRequest) -> Usage:
        contract_id = self.bindings.get(request.agent_id) if isinstance(request.agent_id, str) else None
        if contract_id is None:
            return Usage()
        return Usage(self._steps[contract_id], self._calls[(request.agent_id, request.action)])

    def decide(
        self,
        request: ActionRequest,
        *,
        delegated_by: str | None = None,
        parent_decision_id: str | None = None,
    ) -> tuple[Decision, Usage]:
        """Evaluate a fresh proposal. Consumes one step of the contract budget."""
        with self._lock:
            usage = self.usage_for(request)
            evaluation = evaluate(request, self.contracts, self.bindings, usage, self.clock())
            contract_id = self.bindings.get(request.agent_id) if isinstance(request.agent_id, str) else None
            if contract_id is not None:
                self._steps[contract_id] += 1
            decision = self.record(request, evaluation, delegated_by=delegated_by, parent_decision_id=parent_decision_id)
            return decision, usage

    def record(
        self,
        request: ActionRequest,
        evaluation: PolicyEvaluation,
        *,
        delegated_by: str | None = None,
        parent_decision_id: str | None = None,
        approved_by: str | None = None,
    ) -> Decision:
        """Bind an evaluation to an id, a contract version and the audit trail."""
        with self._lock:
            contract_id = self.bindings.get(request.agent_id) if isinstance(request.agent_id, str) else None
            contract = self.contracts.get(contract_id) if contract_id else None
            decision = Decision(
                decision_id=str(uuid.uuid4()),
                request=request,
                decision=evaluation.decision,
                reason_code=evaluation.reason_code,
                detail=evaluation.detail,
                contract_id=contract_id,
                contract_hash=contract.content_hash if contract else None,
                capability=evaluation.capability,
                rule=evaluation.rule,
                timestamp=self.clock(),
                delegated_by=delegated_by,
                parent_decision_id=parent_decision_id,
                approved_by=approved_by,
            )
            if decision.allowed:
                self._calls[(request.agent_id, request.action)] += 1
            fields = decision.to_dict()
            fields.pop("timestamp")
            fields["requested_contract_id"] = request.contract_id
            if self.audit.include_arguments:
                fields["arguments"] = request.arguments_copy()
            fields["mode"] = "simulate" if self.simulate else "enforce"
            fields["outcome"] = _OUTCOME[decision.decision]
            self.audit.record("decision", **fields)  # raises -> no decision is returned -> nothing executes
            return decision

    def reject_before_policy(self, agent_id: str, action: str, reason: ReasonCode, detail: str) -> Decision:
        """Record a request refused before policy evaluation (e.g. identity mismatch)."""
        request = ActionRequest(agent_id=agent_id or "<unauthenticated>", action=action if isinstance(action, str) else "invalid")
        return self.record(request, PolicyEvaluation(DecisionType.DENY, reason, detail, rule="identity:authentication"))
