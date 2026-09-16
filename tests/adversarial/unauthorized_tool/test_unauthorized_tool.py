"""Test A (contract) and Test C (execution): out-of-contract actions never reach a tool."""

import pytest

from harness import ExecutionRefused, ReasonCode
from helpers import SpyTool, make_harness


def test_A_contract_denies_database_write():
    harness = make_harness()
    result = harness.authorize(agent="researcher", action="database.write", arguments={"table": "users"})
    assert result.denied
    assert result.reason_code is ReasonCode.EXPLICITLY_DENIED


def test_A_unlisted_tool_denied_by_default():
    result = make_harness().authorize(agent="researcher", action="shell.exec", arguments={"cmd": "rm -rf /"})
    assert result.denied and result.reason_code is ReasonCode.TOOL_NOT_ALLOWED


@pytest.mark.parametrize("action", ["database.write", "shell.exec", "create_agent"])
def test_C_denied_action_never_invokes_real_executor(action):
    spy = SpyTool()
    harness = make_harness(tools={action: spy})
    result = harness.authorize(agent="researcher", action=action, arguments={"x": 1})
    assert result.denied
    assert result.grant is None
    with pytest.raises(ExecutionRefused) as refused:
        harness.execute(result)
    assert refused.value.reason == "NO_GRANT"
    assert spy.calls == []  # the proof: the tool was never reached
    assert harness.audit.query(event="execution") == []
    assert harness.audit.query(event="execution_refused", decision_id=result.decision_id)


def test_C_escalated_action_does_not_execute_without_approval():
    spy = SpyTool()
    harness = make_harness(tools={"email.send": spy})
    result = harness.authorize(agent="researcher", action="email.send", arguments={"to": "ceo@example.com"})
    assert result.escalated and result.grant is None
    with pytest.raises(ExecutionRefused):
        harness.execute(result)
    assert spy.calls == []


def test_allowed_action_executes_exactly_once():
    spy = SpyTool(output={"hits": 3})
    harness = make_harness(tools={"web.search": spy})
    result = harness.authorize(agent="researcher", action="web.search", arguments={"query": "x"})
    execution = harness.execute(result)
    assert execution.ok and execution.output == {"hits": 3}
    assert spy.calls == [{"query": "x"}]
    with pytest.raises(ExecutionRefused) as replay:
        harness.execute(result)
    assert replay.value.reason == "GRANT_ALREADY_USED"
    assert len(spy.calls) == 1
