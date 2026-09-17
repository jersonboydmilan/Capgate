"""Capgate — authority management for autonomous software agents.

The agent proposes. The harness authorizes. The executor acts.
"""

from .audit import AuditIntegrityError, AuditLog, load_audit
from .capability import Capability, Effect
from .contract import ContractError, TaskContract, load_contract, load_contracts
from .core import ApprovalError, AuthorizationResult, DelegationResult, Harness, Message, Mode
from .decision import Decision, DecisionType, ReasonCode
from .executor import ExecutionGrant, ExecutionRefused, ExecutionResult
from .policy import evaluate
from .request import ActionRequest, DelegationRequest, MessageRequest

__version__ = "0.1.0"

__all__ = [
    "ActionRequest",
    "ApprovalError",
    "AuditIntegrityError",
    "AuditLog",
    "AuthorizationResult",
    "Capability",
    "ContractError",
    "Decision",
    "DecisionType",
    "DelegationRequest",
    "DelegationResult",
    "Effect",
    "ExecutionGrant",
    "ExecutionRefused",
    "ExecutionResult",
    "Harness",
    "Message",
    "MessageRequest",
    "Mode",
    "ReasonCode",
    "TaskContract",
    "evaluate",
    "load_audit",
    "load_contract",
    "load_contracts",
]
