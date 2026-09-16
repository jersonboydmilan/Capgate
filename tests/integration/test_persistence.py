"""The authority picture survives restarts and is shared by processes on one host."""

import secrets
import threading

import pytest

from harness import AuditLog, ExecutionRefused, Harness, ReasonCode, TaskContract
from harness.state import SQLiteStateStore
from helpers import SpyTool, delegation_contracts, research_contract

KEY = secrets.token_bytes(32)


def contract(max_steps=5, max_calls=None):
    search = {"effect": "allow", "constraints": {"max_calls": max_calls}} if max_calls else "allow"
    return TaskContract.from_dict({
        "contract_id": "c", "goal": "g", "max_steps": max_steps, "approvers": ["alice"],
        "agents": {"w": {"capabilities": {"web.search": search, "email.send": "escalate"}}},
    })


def boot(db, contracts=None, tools=None, **kw):
    """A fresh harness process: new object, same state file and signing key."""
    return Harness(contracts or contract(), tools=tools, state=SQLiteStateStore(db), signing_key=KEY, **kw)


def test_step_budget_survives_restart(tmp_path):
    db = tmp_path / "state.db"
    for _ in range(3):
        assert boot(db).authorize("w", "web.search").allowed
    h = boot(db)
    assert h.authorize("w", "web.search").allowed
    assert h.authorize("w", "shell.exec").denied  # the 5th step
    assert boot(db).authorize("w", "web.search").reason_code is ReasonCode.BUDGET_EXHAUSTED


def test_call_limit_survives_restart(tmp_path):
    db = tmp_path / "state.db"
    assert boot(db, contract(max_steps=50, max_calls=2)).authorize("w", "web.search").allowed
    assert boot(db, contract(max_steps=50, max_calls=2)).authorize("w", "web.search").allowed
    assert boot(db, contract(max_steps=50, max_calls=2)).authorize("w", "web.search").reason_code is ReasonCode.BUDGET_EXHAUSTED


def test_used_grant_cannot_be_replayed_after_restart(tmp_path):
    db = tmp_path / "state.db"
    spy = SpyTool()
    result = boot(db, tools={"web.search": spy}).authorize("w", "web.search", {"q": "x"})
    boot(db, tools={"web.search": spy}).execute_grant(result.grant, result.request)  # executes after a restart
    with pytest.raises(ExecutionRefused) as refused:
        boot(db, tools={"web.search": spy}).execute_grant(result.grant, result.request)
    assert refused.value.reason == "GRANT_ALREADY_USED"
    assert len(spy.calls) == 1


def test_pending_escalation_survives_restart_and_is_single_use(tmp_path):
    db = tmp_path / "state.db"
    spy = SpyTool()
    pending = boot(db, tools={"email.send": spy}).authorize("w", "email.send", {"to": "team@example.com"})

    restarted = boot(db, tools={"email.send": spy})
    assert [p.approval_id for p in restarted.pending_approvals()] == [pending.approval_id]
    assert restarted.pending_approvals()[0].decision.request.arguments == {"to": "team@example.com"}
    approved = restarted.approve(pending.approval_id, "alice", "ok")
    restarted.execute(approved)
    assert spy.calls == [{"to": "team@example.com"}]

    again = boot(db, tools={"email.send": spy})
    assert again.pending_approvals() == []
    record = again.approval_record(pending.approval_id)
    assert (record["status"], record["verdict"], record["approver"]) == ("decided", "granted", "alice")
    from harness import ApprovalError
    with pytest.raises(ApprovalError):
        again.approve(pending.approval_id, "alice")


def test_undelivered_messages_survive_restart(tmp_path):
    db = tmp_path / "state.db"
    boot(db, delegation_contracts()).send_message("agent-a", "agent-b", "hello")
    assert [m.body for m in boot(db, delegation_contracts()).receive("agent-b")] == ["hello"]
    assert boot(db, delegation_contracts()).receive("agent-b") == []


def test_failed_audit_write_does_not_consume_budget(tmp_path):
    db = tmp_path / "state.db"
    broken = boot(db, audit=AuditLog(tmp_path / "missing" / "audit.jsonl"))
    with pytest.raises(OSError):
        broken.authorize("w", "web.search")
    assert SQLiteStateStore(db).steps("c") == 0


def test_concurrent_harness_instances_share_one_budget(tmp_path):
    db = tmp_path / "state.db"
    instances = [boot(db, contract(max_steps=30)) for _ in range(3)]
    results = []
    lock = threading.Lock()

    def worker(h):
        for _ in range(15):
            r = h.authorize("w", "web.search")
            with lock:
                results.append(r.reason_code)

    threads = [threading.Thread(target=worker, args=(h,)) for h in instances for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 90
    assert results.count(ReasonCode.CAPABILITY_GRANTED) == 30
    assert results.count(ReasonCode.BUDGET_EXHAUSTED) == 60
