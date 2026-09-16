"""Deny-by-default policy engine.

`evaluate` is a pure function: same request, contracts, usage and time in,
same PolicyEvaluation out. It has no parameter for a requester, delegator or
"on behalf of" principal — delegation cannot influence the answer because the
engine has no way to see it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from .capability import RESERVED_PREFIXES, Effect, check_constraints
from .contract import TaskContract
from .decision import DecisionType, PolicyEvaluation, ReasonCode
from .request import DELEGATE_ACTION, MESSAGE_ACTION, ActionRequest

DENY, ALLOW, ESCALATE = DecisionType.DENY, DecisionType.ALLOW, DecisionType.ESCALATE


@dataclass(frozen=True)
class Usage:
    """Counters consumed by budget rules, captured before evaluation."""

    contract_steps: int = 0
    action_calls: int = 0


def evaluate(
    request: ActionRequest,
    contracts: Mapping[str, TaskContract],
    bindings: Mapping[str, str],
    usage: Usage,
    now: datetime,
) -> PolicyEvaluation:
    problems = request.problems()
    if problems:
        return PolicyEvaluation(DENY, ReasonCode.MALFORMED_REQUEST, "; ".join(problems), rule="request:schema")

    bound_id = bindings.get(request.agent_id)
    if bound_id is None:
        return PolicyEvaluation(DENY, ReasonCode.UNKNOWN_AGENT, f"agent {request.agent_id!r} is not bound to any contract", rule="identity:binding")
    contract = contracts[bound_id]

    if request.contract_id is not None and request.contract_id != bound_id:
        return PolicyEvaluation(DENY, ReasonCode.CONTRACT_MISMATCH, f"agent is bound to {bound_id!r}, not {request.contract_id!r}", rule="identity:binding")

    if contract.expires_at is not None and now >= contract.expires_at:
        return PolicyEvaluation(DENY, ReasonCode.CONTRACT_EXPIRED, f"contract expired at {contract.expires_at.isoformat()}", rule="contract:expires_at")

    if contract.max_steps is not None and usage.contract_steps >= contract.max_steps:
        return PolicyEvaluation(DENY, ReasonCode.BUDGET_EXHAUSTED, f"contract step budget of {contract.max_steps} exhausted", rule="contract:max_steps")

    if request.action.startswith(RESERVED_PREFIXES):
        return PolicyEvaluation(DENY, ReasonCode.RESERVED_ACTION, "agents cannot act on the harness or on contracts", rule="invariant:contract_immutable")

    capability = contract.capabilities_for(request.agent_id).get(request.action)
    if capability is None:
        return PolicyEvaluation(DENY, ReasonCode.TOOL_NOT_ALLOWED, f"no capability for {request.action!r} under {bound_id!r}", rule="default:deny")

    if capability.effect is Effect.DENY:
        return PolicyEvaluation(DENY, ReasonCode.EXPLICITLY_DENIED, f"{request.action!r} is explicitly denied", capability=request.action, rule="capability:deny")

    if capability.expires_at is not None and now >= capability.expires_at:
        return PolicyEvaluation(DENY, ReasonCode.CAPABILITY_EXPIRED, f"capability expired at {capability.expires_at.isoformat()}", capability=request.action, rule="capability:expires_at")

    violation = check_constraints(capability, request, usage.action_calls)
    if violation is not None:
        return PolicyEvaluation(DENY, violation.reason_code, violation.detail, capability=request.action, rule=violation.rule)

    if request.action in (MESSAGE_ACTION, DELEGATE_ACTION):
        target = request.arguments.get("to")
        if target == request.agent_id:
            return PolicyEvaluation(DENY, ReasonCode.TARGET_NOT_ALLOWED, "an agent cannot message or delegate to itself", capability=request.action, rule="invariant:no_self_delegation")
        if target not in bindings:
            return PolicyEvaluation(DENY, ReasonCode.TARGET_NOT_ALLOWED, f"target {target!r} is not a registered agent", capability=request.action, rule="identity:binding")

    if capability.effect is Effect.ESCALATE:
        return PolicyEvaluation(ESCALATE, ReasonCode.REQUIRES_APPROVAL, f"{request.action!r} requires human approval", capability=request.action, rule="capability:escalate")

    return PolicyEvaluation(ALLOW, ReasonCode.CAPABILITY_GRANTED, f"{request.action!r} granted by {bound_id!r}", capability=request.action, rule="capability:allow")
