import pytest

from capgate import ExecutionRefused, ReasonCode, TaskContract
from helpers import FakeClock, SpyTool, T0, make_harness


def contract(**cap_extra):
    return TaskContract.from_dict({
        "contract_id": "short-lived",
        "goal": "g", "max_steps": 50,
        "expires_at": "2026-09-01T14:00:00Z",
        "agents": {"worker": {"capabilities": {
            "web.search": "allow",
            "deploy.run": {"effect": "allow", "expires_at": "2026-09-01T12:30:00Z"},
        }}},
    })


def test_capability_expires():
    clock = FakeClock()
    harness = make_harness(contract(), clock=clock)
    assert harness.authorize("worker", "deploy.run").allowed
    clock.advance(minutes=30)
    result = harness.authorize("worker", "deploy.run")
    assert result.denied and result.reason_code is ReasonCode.CAPABILITY_EXPIRED
    assert harness.authorize("worker", "web.search").allowed


def test_contract_expires():
    clock = FakeClock()
    harness = make_harness(contract(), clock=clock)
    clock.advance(hours=2)
    result = harness.authorize("worker", "web.search")
    assert result.denied and result.reason_code is ReasonCode.CONTRACT_EXPIRED


def test_grant_expires_before_execution():
    clock = FakeClock()
    spy = SpyTool()
    harness = make_harness(contract(), clock=clock, tools={"web.search": spy}, grant_ttl_seconds=5)
    result = harness.authorize("worker", "web.search", {"q": "x"})
    clock.advance(seconds=6)
    with pytest.raises(ExecutionRefused) as refused:
        harness.execute(result)
    assert refused.value.reason == "GRANT_EXPIRED"
    assert spy.calls == []


def test_approval_rechecks_expiry():
    clock = FakeClock()
    c = TaskContract.from_dict({
        "contract_id": "c", "goal": "g", "max_steps": 50, "approvers": ["alice"],
        "agents": {"worker": {"capabilities": {"prod.deploy": {"effect": "escalate", "expires_at": "2026-09-01T12:10:00Z"}}}},
    })
    harness = make_harness(c, clock=clock)
    pending = harness.authorize("worker", "prod.deploy")
    clock.advance(minutes=15)  # approval arrives after the capability expired
    result = harness.approve(pending.approval_id, "alice")
    assert result.denied and result.reason_code is ReasonCode.CAPABILITY_EXPIRED
