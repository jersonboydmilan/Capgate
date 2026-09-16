"""Test D and invariant 3: delegation does not transfer authority."""

import pytest

from harness import ReasonCode
from helpers import SpyTool, delegation_contracts, make_harness


def test_D_canonical_demo_denied_under_agent_b_contract():
    """Agent A → "ask Agent B to perform database.write" → evaluated under B → DENIED."""
    spy = SpyTool()
    harness = make_harness(delegation_contracts(), tools={"database.write": spy})
    result = harness.delegate("agent-a", "agent-b", "database.write", {"table": "users", "row": {"admin": True}})

    assert result.delegation.allowed  # A may ask
    assert result.action is not None
    assert result.action.denied
    assert result.reason_code is ReasonCode.TOOL_NOT_ALLOWED
    assert result.blocked_at == "recipient"
    assert result.action.decision.contract_id == "contract-b"  # evaluated under B's contract
    assert result.action.request.agent_id == "agent-b"
    assert result.action.decision.delegated_by == "agent-a"  # recorded, never used for authority
    assert spy.calls == []

    record = harness.audit.query(event="decision", decision_id=result.action.decision_id)[0]
    assert record["contract_id"] == "contract-b"
    assert record["delegated_by"] == "agent-a"
    assert record["parent_decision_id"] == result.delegation.decision_id


def test_senders_authority_never_flows_to_recipient():
    """A holds web.fetch; B does not. Delegating web.fetch to B must not work."""
    harness = make_harness(delegation_contracts(a_may_request=("web.fetch",)))
    assert harness.authorize("agent-a", "web.fetch", {"url": "https://example.com"}).allowed
    result = harness.delegate("agent-a", "agent-b", "web.fetch", {"url": "https://example.com"})
    assert not result.allowed and result.blocked_at == "recipient"
    assert result.reason_code is ReasonCode.TOOL_NOT_ALLOWED


def test_recipient_acts_only_on_its_own_authority():
    """B's contract grants database.write; A's denies it. B's own grant decides."""
    spy = SpyTool()
    harness = make_harness(delegation_contracts(b_can_write=True), tools={"database.write": spy})
    assert harness.authorize("agent-a", "database.write").denied
    result = harness.delegate("agent-a", "agent-b", "database.write", {"table": "notes"})
    assert result.allowed
    assert result.action.decision.contract_id == "contract-b"
    harness.execute(result.action)
    assert spy.calls == [{"table": "notes"}]


def test_sender_may_only_request_actions_it_was_scoped_to_request():
    harness = make_harness(delegation_contracts(b_can_write=True, a_may_request=("web.search",)))
    result = harness.delegate("agent-a", "agent-b", "database.write", {})
    assert result.blocked_at == "sender"
    assert result.reason_code is ReasonCode.DELEGATED_ACTION_NOT_ALLOWED
    assert result.action is None  # B's contract was never even consulted


@pytest.mark.parametrize("target", ["agent-c", "researcher", "agent-a"])
def test_delegation_to_unlisted_or_self_target_denied(target):
    harness = make_harness(delegation_contracts())
    result = harness.delegate("agent-a", target, "web.search", {})
    assert result.blocked_at == "sender"
    assert result.reason_code is ReasonCode.TARGET_NOT_ALLOWED


def test_agent_without_delegate_capability_cannot_delegate():
    harness = make_harness(delegation_contracts())
    result = harness.delegate("agent-b", "agent-a", "web.fetch", {"url": "https://example.com"})
    assert result.blocked_at == "sender" and result.reason_code is ReasonCode.TOOL_NOT_ALLOWED


def test_delegation_chain_does_not_launder_authority():
    """A → B → C: C still acts only under C's contract, B only under B's."""
    from harness import TaskContract

    a = TaskContract.from_dict({"contract_id": "ca", "goal": "g", "agents": {"a": {"capabilities": {
        "database.write": "allow",
        "agent.delegate": {"effect": "allow", "constraints": {"allowed_targets": ["b"], "allowed_actions": ["agent.delegate", "database.write"]}},
    }}}})
    b = TaskContract.from_dict({"contract_id": "cb", "goal": "g", "agents": {"b": {"capabilities": {
        "agent.delegate": {"effect": "allow", "constraints": {"allowed_targets": ["c"], "allowed_actions": ["database.write"]}},
    }}}})
    c = TaskContract.from_dict({"contract_id": "cc", "goal": "g", "agents": {"c": {"capabilities": {"web.search": "allow"}}}})
    harness = make_harness([a, b, c])
    hop = harness.delegate("b", "c", "database.write", {})
    assert hop.blocked_at == "recipient" and hop.action.decision.contract_id == "cc"
