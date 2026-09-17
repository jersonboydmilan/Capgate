"""Invariant 2: the agent cannot expand its own TaskContract."""

import pytest

from capgate import ActionRequest, ExecutionRefused, ReasonCode
from capgate.executor import ExecutionGrant
from helpers import SpyTool, delegation_contracts, make_harness


@pytest.mark.parametrize("action", ["contract.update", "contract.grant", "harness.approve", "harness.disable"])
def test_reserved_actions_denied(action):
    result = make_harness().authorize(agent="researcher", action=action, arguments={"capability": "database.write"})
    assert result.denied and result.reason_code is ReasonCode.RESERVED_ACTION


def test_agent_cannot_select_a_more_permissive_contract():
    harness = make_harness(delegation_contracts(b_can_write=True))
    # agent-a claims to act under contract-b, which grants database.write
    result = harness.authorize(agent="agent-a", action="database.write", arguments={}, contract_id="contract-b")
    assert result.denied and result.reason_code is ReasonCode.CONTRACT_MISMATCH


def test_arguments_claiming_authority_are_just_data():
    result = make_harness().authorize(
        agent="researcher", action="database.write",
        arguments={"capabilities": {"database.write": "allow"}, "authorized": True, "role": "admin"},
    )
    assert result.denied and result.reason_code is ReasonCode.EXPLICITLY_DENIED


def test_grant_cannot_be_retargeted_to_another_action():
    spy = SpyTool()
    harness = make_harness(tools={"web.search": SpyTool(), "database.write": spy})
    result = harness.authorize(agent="researcher", action="web.search", arguments={"q": "x"})
    forged = ExecutionGrant(**{**result.grant.payload(), "action": "database.write"}, signature=result.grant.signature)
    with pytest.raises(ExecutionRefused) as refused:
        harness.execute_grant(forged, ActionRequest("researcher", "database.write", {"q": "x"}))
    assert refused.value.reason == "INVALID_GRANT_SIGNATURE"
    assert spy.calls == []


def test_grant_from_another_harness_rejected():
    spy = SpyTool()
    victim = make_harness(tools={"web.search": spy})
    attacker_harness = make_harness(tools={"web.search": SpyTool()})
    stolen = attacker_harness.authorize(agent="researcher", action="web.search", arguments={"q": "x"})
    with pytest.raises(ExecutionRefused) as refused:
        victim.execute_grant(stolen.grant, stolen.request)
    assert refused.value.reason == "INVALID_GRANT_SIGNATURE"
    assert spy.calls == []
