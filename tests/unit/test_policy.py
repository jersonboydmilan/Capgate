"""The policy engine is a pure, deterministic, deny-by-default function."""

import pytest

from harness import ActionRequest, DecisionType, ReasonCode, TaskContract, evaluate
from harness.contract import build_bindings
from harness.policy import Usage
from helpers import T0, research_contract


def decide(action, arguments=None, *, agent="researcher", contract=None, usage=Usage(), now=T0, contract_id=None):
    contracts, bindings = build_bindings([contract or research_contract()])
    return evaluate(ActionRequest(agent, action, arguments or {}, contract_id), contracts, bindings, usage, now)


def test_granted_capability_allows():
    result = decide("web.search", {"query": "x"})
    assert (result.decision, result.reason_code) == (DecisionType.ALLOW, ReasonCode.CAPABILITY_GRANTED)


def test_unlisted_action_is_denied_by_default():
    result = decide("filesystem.delete")
    assert (result.decision, result.reason_code, result.rule) == (DecisionType.DENY, ReasonCode.TOOL_NOT_ALLOWED, "default:deny")


def test_explicit_deny():
    assert decide("database.write").reason_code is ReasonCode.EXPLICITLY_DENIED


def test_escalate():
    result = decide("email.send", {"to": "x@example.com"})
    assert (result.decision, result.reason_code) == (DecisionType.ESCALATE, ReasonCode.REQUIRES_APPROVAL)


def test_unknown_agent_denied():
    assert decide("web.search", agent="stranger").reason_code is ReasonCode.UNKNOWN_AGENT


def test_malformed_action_name_denied():
    assert decide("Web Search!").reason_code is ReasonCode.MALFORMED_REQUEST


def test_deterministic():
    results = {decide("web.fetch", {"url": "http://10.0.0.1/"}) for _ in range(50)}
    assert len(results) == 1


def test_escalate_still_subject_to_constraints():
    contract = TaskContract.from_dict({
        "contract_id": "c", "goal": "g", "max_steps": 50,
        "agents": {"researcher": {"capabilities": {"payments.send": {"effect": "escalate", "constraints": {"allowed_arguments": ["amount"]}}}}},
    })
    result = decide("payments.send", {"amount": 5, "to_account": "attacker"}, contract=contract)
    assert result.reason_code is ReasonCode.ARGUMENT_NOT_ALLOWED  # never reaches a human


def test_policy_has_no_delegator_input():
    """Structural guarantee for invariant 3: evaluate() cannot see who asked."""
    import inspect

    params = set(inspect.signature(evaluate).parameters)
    assert params == {"request", "contracts", "bindings", "usage", "now"}
    fields = set(ActionRequest.__dataclass_fields__)
    assert fields == {"agent_id", "action", "arguments", "contract_id"}
