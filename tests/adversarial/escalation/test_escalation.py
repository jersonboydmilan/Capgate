"""Human-approval path: fully auditable, decided only by designated approvers."""

import pytest

from harness import ApprovalError, DelegationResult, ReasonCode, TaskContract
from helpers import SpyTool, make_harness


def test_approval_executes_and_is_fully_auditable():
    spy = SpyTool()
    harness = make_harness(tools={"email.send": spy})
    pending = harness.authorize("researcher", "email.send", {"to": "team@example.com"})
    assert pending.escalated and pending.approval_id
    assert [p.approval_id for p in harness.pending_approvals()] == [pending.approval_id]

    approved = harness.approve(pending.approval_id, "alice", "reviewed recipients")
    assert approved.allowed and approved.reason_code is ReasonCode.APPROVED_BY_HUMAN
    assert approved.decision.approved_by == "alice"
    assert approved.decision.parent_decision_id == pending.decision_id
    harness.execute(approved)
    assert spy.calls == [{"to": "team@example.com"}]

    audit = harness.audit
    [approval] = audit.query(event="approval")
    assert (approval["approver"], approval["verdict"], approval["note"]) == ("alice", "granted", "reviewed recipients")
    assert approval["decision_id"] == pending.decision_id
    assert approval["resulting_decision_id"] == approved.decision_id
    assert [r["event"] for r in audit.for_decision(approved.decision_id)] == ["decision", "execution"]
    assert harness.pending_approvals() == []


def test_rejection_is_recorded_and_blocks():
    spy = SpyTool()
    harness = make_harness(tools={"email.send": spy})
    pending = harness.authorize("researcher", "email.send", {"to": "everyone@example.com"})
    rejected = harness.reject(pending.approval_id, "alice", "too broad")
    assert rejected.denied and rejected.reason_code is ReasonCode.APPROVAL_REJECTED
    assert harness.audit.query(event="approval", verdict="rejected")
    assert spy.calls == []


@pytest.mark.parametrize("approver", ["researcher", "mallory", ""])
def test_only_designated_approvers_can_decide(approver):
    harness = make_harness()
    pending = harness.authorize("researcher", "email.send", {"to": "x"})
    with pytest.raises(ApprovalError):
        harness.approve(pending.approval_id, approver)
    assert harness.audit.query(event="approval_refused", reason_code="UNAUTHORIZED_APPROVER")
    assert len(harness.pending_approvals()) == 1  # still pending, still blocked


def test_approval_is_single_use():
    harness = make_harness()
    pending = harness.authorize("researcher", "email.send", {"to": "x"})
    harness.approve(pending.approval_id, "alice")
    with pytest.raises(ApprovalError):
        harness.approve(pending.approval_id, "alice")


def test_approver_of_one_contract_cannot_approve_another():
    a = TaskContract.from_dict({"contract_id": "a", "goal": "g", "max_steps": 50, "approvers": ["alice"], "agents": {"x": {"capabilities": {"prod.deploy": "escalate"}}}})
    b = TaskContract.from_dict({"contract_id": "b", "goal": "g", "max_steps": 50, "approvers": ["bob"], "agents": {"y": {"capabilities": {"prod.deploy": "escalate"}}}})
    harness = make_harness([a, b])
    pending = harness.authorize("x", "prod.deploy")
    with pytest.raises(ApprovalError):
        harness.approve(pending.approval_id, "bob")


def test_escalated_delegation_continues_to_recipient_evaluation_after_approval():
    a = TaskContract.from_dict({"contract_id": "a", "goal": "g", "max_steps": 50, "approvers": ["alice"], "agents": {"lead": {"capabilities": {
        "agent.delegate": {"effect": "escalate", "constraints": {"allowed_targets": ["worker"], "allowed_actions": ["database.write"]}},
    }}}})
    b = TaskContract.from_dict({"contract_id": "b", "goal": "g", "max_steps": 50, "agents": {"worker": {"capabilities": {"web.search": "allow"}}}})
    harness = make_harness([a, b])
    first = harness.delegate("lead", "worker", "database.write", {})
    assert first.delegation.escalated
    outcome = harness.approve(first.delegation.approval_id, "alice")
    assert isinstance(outcome, DelegationResult)
    assert outcome.delegation.allowed  # human approved the *request*...
    assert outcome.action.denied and outcome.action.decision.contract_id == "b"  # ...not the recipient's authority
