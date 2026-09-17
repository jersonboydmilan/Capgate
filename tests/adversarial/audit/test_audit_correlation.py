"""Test E: every decision produces a correlated, complete audit record."""

import pytest

from capgate import AuditLog, ReasonCode
from helpers import SpyTool, delegation_contracts, make_harness

REQUIRED = {"decision_id", "decision", "reason_code", "agent_id", "contract_id", "contract_hash", "action", "arguments_hash", "capability", "policy_rule", "outcome", "timestamp", "hash", "prev_hash"}


def test_E_deny_record_correlates_to_decision():
    audit = AuditLog()
    harness = make_harness(delegation_contracts(), audit=audit)
    result = harness.delegate("agent-a", "agent-b", "database.write", {})
    decision = result.action.decision

    [record] = audit.for_decision(decision.decision_id)
    assert {k: record[k] for k in ("decision", "reason_code", "agent_id", "contract_id", "action", "decision_id")} == {
        "decision": "deny",
        "reason_code": "TOOL_NOT_ALLOWED",
        "agent_id": "agent-b",
        "contract_id": "contract-b",
        "action": "database.write",
        "decision_id": decision.decision_id,
    }
    assert REQUIRED <= set(record)
    assert record["arguments_hash"] == decision.request.arguments_hash
    assert record["contract_hash"] == decision.contract_hash


@pytest.mark.parametrize("action, expected", [("web.search", "allow"), ("database.write", "deny"), ("email.send", "escalate")])
def test_E_every_decision_type_is_recorded(action, expected):
    audit = AuditLog()
    harness = make_harness(audit=audit)
    result = harness.authorize("researcher", action, {"q": 1})
    records = audit.for_decision(result.decision_id)
    assert [r["decision"] for r in records] == [expected]
    assert records[0]["reason_code"] == result.reason_code.value


def test_E_execution_outcome_correlates_with_decision():
    audit = AuditLog()
    harness = make_harness(audit=audit, tools={"web.search": SpyTool()})
    result = harness.authorize("researcher", "web.search", {"q": "x"})
    harness.execute(result)
    events = [r["event"] for r in audit.for_decision(result.decision_id)]
    assert events == ["decision", "execution"]
    assert audit.for_decision(result.decision_id)[1]["outcome"] == "succeeded"


def test_E_audit_failure_blocks_execution(tmp_path):
    spy = SpyTool()
    audit = AuditLog(tmp_path / "gone" / "audit.jsonl")  # unwritable
    harness = make_harness(audit=audit, tools={"web.search": spy})
    with pytest.raises(OSError):
        harness.authorize("researcher", "web.search", {"q": "x"})
    assert spy.calls == []


def test_E_tool_failure_is_recorded_as_outcome():
    def broken(_):
        raise TimeoutError("upstream timed out")

    audit = AuditLog()
    harness = make_harness(audit=audit, tools={"web.search": broken})
    result = harness.authorize("researcher", "web.search", {"q": "x"})
    execution = harness.execute(result)
    assert execution.status == "failed"
    [rec] = audit.query(event="execution", decision_id=result.decision_id)
    assert rec["outcome"] == "failed" and "TimeoutError" in rec["error"]


def test_audit_contains_no_reasoning_fields():
    audit = AuditLog()
    make_harness(audit=audit).authorize("researcher", "web.search", {"q": "x"})
    keys = set(audit.records()[0])
    assert not keys & {"reasoning", "chain_of_thought", "thoughts", "prompt"}
