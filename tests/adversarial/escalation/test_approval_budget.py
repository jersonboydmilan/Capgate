"""Regression: approving an escalation must re-check the CURRENT budget, not the snapshot.

Between escalation and approval, other actions spend budget (on this host or,
in a multi-host deployment, another). The approval must be evaluated against
the counters as they stand at approval time.
"""

import pytest

from capgate import ReasonCode, TaskContract
from helpers import SpyTool, make_harness


def contract(max_steps=None, max_calls=None):
    email = {"effect": "escalate"}
    if max_calls is not None:
        email = {"effect": "escalate", "constraints": {"max_calls": max_calls}}
    data = {"contract_id": "c", "goal": "g", "max_steps": max_steps or 50, "approvers": ["alice"],
            "agents": {"researcher": {"capabilities": {"web.search": "allow", "email.send": email}}}}
    return TaskContract.from_dict(data)


def test_step_budget_exhausted_after_escalation_blocks_approval():
    harness = make_harness(contract(max_steps=4), tools={"email.send": SpyTool()})
    pending = harness.authorize("researcher", "email.send", {"to": "x"})   # step 1, escalated
    assert pending.escalated
    # spend the rest of the contract's step budget while the approval waits
    for _ in range(5):
        harness.authorize("researcher", "web.search", {"q": "x"})
    result = harness.approve(pending.approval_id, "alice")
    assert result.denied and result.reason_code is ReasonCode.BUDGET_EXHAUSTED


def test_call_limit_reached_after_escalation_blocks_approval():
    harness = make_harness(contract(max_steps=50, max_calls=1), tools={"email.send": SpyTool()})
    first = harness.authorize("researcher", "email.send", {"to": "a"})     # escalated, no call spent yet
    second = harness.authorize("researcher", "email.send", {"to": "b"})    # escalated
    # approve the second first: consumes the one allowed call
    r2 = harness.approve(second.approval_id, "alice")
    assert r2.allowed
    # the first can no longer be approved: max_calls=1 already used
    r1 = harness.approve(first.approval_id, "alice")
    assert r1.denied and r1.reason_code is ReasonCode.BUDGET_EXHAUSTED


def test_approval_within_budget_still_succeeds():
    harness = make_harness(contract(max_steps=50), tools={"email.send": SpyTool({"sent": True})})
    pending = harness.authorize("researcher", "email.send", {"to": "team"})
    result = harness.approve(pending.approval_id, "alice")
    assert result.allowed and result.reason_code is ReasonCode.APPROVED_BY_HUMAN
