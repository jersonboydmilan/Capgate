"""In-process bypass attempts against the executor.

In-process code is trusted by construction (it could monkeypatch anything);
these tests pin down the executor's own checks. The process-level acceptance
test lives in tests/bypass/.
"""

import pytest

from capgate import ActionRequest, ExecutionRefused
from capgate.core import AuthorizationResult
from capgate.executor import ExecutionGrant
from helpers import SpyTool, make_harness


def test_hand_built_allow_result_without_grant_refused():
    spy = SpyTool()
    harness = make_harness(tools={"database.write": spy})
    denied = harness.authorize("researcher", "database.write", {"x": 1})
    forged = AuthorizationResult(denied.decision)  # no grant
    with pytest.raises(ExecutionRefused):
        harness.execute(forged)
    assert spy.calls == []


def test_unsigned_grant_refused():
    spy = SpyTool()
    harness = make_harness(tools={"database.write": spy})
    request = ActionRequest("researcher", "database.write", {"x": 1})
    grant = ExecutionGrant("fake", "researcher", "research-v1", "database.write", request.arguments_hash, 9e12, "00" * 32)
    with pytest.raises(ExecutionRefused) as refused:
        harness.execute_grant(grant, request)
    assert refused.value.reason == "INVALID_GRANT_SIGNATURE"
    assert spy.calls == []
    assert harness.audit.query(event="execution_refused", reason_code="INVALID_GRANT_SIGNATURE")


def test_grant_cannot_be_used_by_another_agent():
    from helpers import delegation_contracts

    spy = SpyTool()
    harness = make_harness(delegation_contracts(), tools={"web.search": spy})
    result = harness.authorize("agent-a", "web.search", {"q": "x"})
    with pytest.raises(ExecutionRefused) as refused:
        harness.execute_grant(result.grant, ActionRequest("agent-b", "web.search", {"q": "x"}))
    assert refused.value.reason == "GRANT_REQUEST_MISMATCH"
    assert spy.calls == []


def test_simulation_mode_never_executes():
    spy = SpyTool()
    harness = make_harness(tools={"web.search": spy}, mode="simulate")
    result = harness.authorize("researcher", "web.search", {"q": "x"})
    assert result.allowed and result.grant is None
    with pytest.raises(ExecutionRefused) as refused:
        harness.execute(result)
    assert refused.value.reason == "SIMULATION_MODE"
    assert spy.calls == []


def test_harness_owned_actions_cannot_be_overridden_by_tools():
    with pytest.raises(ValueError):
        make_harness(tools={"agent.message": SpyTool()})
