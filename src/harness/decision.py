"""Structured, reason-coded authorization decisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from .request import ActionRequest


class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class ReasonCode(str, Enum):
    # allow
    CAPABILITY_GRANTED = "CAPABILITY_GRANTED"
    APPROVED_BY_HUMAN = "APPROVED_BY_HUMAN"
    # escalate
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    # deny: identity and contract
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"
    CONTRACT_EXPIRED = "CONTRACT_EXPIRED"
    RESERVED_ACTION = "RESERVED_ACTION"
    # deny: capability
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    EXPLICITLY_DENIED = "EXPLICITLY_DENIED"
    CAPABILITY_EXPIRED = "CAPABILITY_EXPIRED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    # deny: policy constraints
    ARGUMENT_NOT_ALLOWED = "ARGUMENT_NOT_ALLOWED"
    ARGUMENT_MISSING = "ARGUMENT_MISSING"
    DOMAIN_NOT_ALLOWED = "DOMAIN_NOT_ALLOWED"
    TARGET_NOT_ALLOWED = "TARGET_NOT_ALLOWED"
    DELEGATED_ACTION_NOT_ALLOWED = "DELEGATED_ACTION_NOT_ALLOWED"
    # deny: delegation / approval
    DELEGATION_NOT_AUTHORIZED = "DELEGATION_NOT_AUTHORIZED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"


@dataclass(frozen=True)
class PolicyEvaluation:
    """Output of the pure policy engine. Deterministic for identical inputs."""

    decision: DecisionType
    reason_code: ReasonCode
    detail: str
    capability: str | None = None
    rule: str | None = None


@dataclass(frozen=True)
class Decision:
    """A PolicyEvaluation bound to an identity, a contract version and a time."""

    decision_id: str
    request: ActionRequest
    decision: DecisionType
    reason_code: ReasonCode
    detail: str
    contract_id: str | None
    contract_hash: str | None
    capability: str | None
    rule: str | None
    timestamp: datetime
    delegated_by: str | None = None
    parent_decision_id: str | None = None
    approved_by: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is DecisionType.ALLOW

    @property
    def denied(self) -> bool:
        return self.decision is DecisionType.DENY

    @property
    def escalated(self) -> bool:
        return self.decision is DecisionType.ESCALATE

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "detail": self.detail,
            "agent_id": self.request.agent_id,
            "contract_id": self.contract_id,
            "contract_hash": self.contract_hash,
            "action": self.request.action,
            "arguments_hash": self.request.arguments_hash,
            "capability": self.capability,
            "policy_rule": self.rule,
            "delegated_by": self.delegated_by,
            "parent_decision_id": self.parent_decision_id,
            "approved_by": self.approved_by,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_record(self) -> dict[str, Any]:
        """Lossless form for persistence (includes the full request)."""
        return {**self.to_dict(), "request": self.request.to_dict()}

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "Decision":
        req = record["request"]
        return cls(
            decision_id=record["decision_id"],
            request=ActionRequest(req["agent_id"], req["action"], req["arguments"], req["contract_id"]),
            decision=DecisionType(record["decision"]),
            reason_code=ReasonCode(record["reason_code"]),
            detail=record["detail"],
            contract_id=record["contract_id"],
            contract_hash=record["contract_hash"],
            capability=record["capability"],
            rule=record["policy_rule"],
            timestamp=datetime.fromisoformat(record["timestamp"]),
            delegated_by=record.get("delegated_by"),
            parent_decision_id=record.get("parent_decision_id"),
            approved_by=record.get("approved_by"),
        )
