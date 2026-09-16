"""SDK and raw HTTP converge on the same policy/executor path."""

import json
import secrets
import urllib.request

import pytest

from harness import AuditLog, Harness
from harness.server import HarnessServer
from harness_client import HarnessClient
from helpers import SpyTool, delegation_contracts, research_contract


@pytest.fixture
def stack():
    spy = SpyTool({"hits": 1})
    harness = Harness(research_contract(), tools={"web.search": spy, "email.send": spy}, audit=AuditLog())
    tokens = {"researcher": secrets.token_urlsafe(24)}
    approvers = {"alice": secrets.token_urlsafe(24)}
    server = HarnessServer(harness, tokens, approvers).start()
    yield server, tokens, approvers, spy
    server.stop()


def test_sdk_allow_deny_escalate_approve(stack):
    server, tokens, approvers, spy = stack
    agent = HarnessClient(server.url, tokens["researcher"])
    alice = HarnessClient(server.url, approvers["alice"])

    ok = agent.act("web.search", {"query": "x"})
    assert ok.allowed and ok.execution["output"] == {"hits": 1}

    denied = agent.act("database.write", {"row": 1})
    assert denied.status == 403 and denied.reason_code == "EXPLICITLY_DENIED"

    pending = agent.act("email.send", {"to": "team@example.com"})
    assert pending.escalated
    assert [a["approval_id"] for a in alice.pending_approvals()] == [pending.approval_id]
    assert agent.pending_approvals() == []  # agents cannot list or decide approvals

    decided = alice.decide_approval(pending.approval_id, True, "fine")
    assert decided.allowed and decided.execution["status"] == "succeeded"
    status = agent.approval_status(pending.approval_id)
    assert status.body["status"] == "decided"
    assert spy.calls == [{"query": "x"}, {"to": "team@example.com"}]


def test_raw_http_gets_identical_decision_to_sdk(stack):
    server, tokens, _, _ = stack
    req = urllib.request.Request(
        f"{server.url}/v1/actions",
        data=json.dumps({"action": "database.write", "arguments": {"row": 1}}).encode(),
        headers={"Authorization": f"Bearer {tokens['researcher']}"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req)
    assert json.loads(err.value.read())["reason_code"] == HarnessClient(server.url, tokens["researcher"]).act("database.write", {"row": 1}).reason_code


def test_messages_and_delegation_over_http():
    harness = Harness(delegation_contracts(), audit=AuditLog())
    tokens = {"agent-a": secrets.token_urlsafe(24), "agent-b": secrets.token_urlsafe(24)}
    server = HarnessServer(harness, tokens).start()
    try:
        a, b = HarnessClient(server.url, tokens["agent-a"]), HarnessClient(server.url, tokens["agent-b"])
        assert a.send_message("agent-b", "hi").allowed
        assert [m["body"] for m in b.receive()] == ["hi"]
        assert b.send_message("agent-a", "hi").status == 403
        d = a.delegate("agent-b", "database.write", {"row": 1})
        assert d.status == 403 and d.body["blocked_at"] == "recipient" and d.reason_code == "TOOL_NOT_ALLOWED"
    finally:
        server.stop()


def test_server_rejects_weak_or_unknown_tokens():
    harness = Harness(research_contract())
    with pytest.raises(ValueError):
        HarnessServer(harness, {"researcher": "short"})
    with pytest.raises(ValueError):
        HarnessServer(harness, {"ghost": secrets.token_urlsafe(24)})
