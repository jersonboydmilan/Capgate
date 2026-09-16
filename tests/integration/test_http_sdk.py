"""SDK and raw HTTP converge on the same policy/executor path."""

import json
import secrets
import urllib.request

import pytest

from harness import AuditLog, Harness
from harness.identity import Keyring, TokenAuthority
from harness.server import HarnessServer
from harness_client import HarnessClient
from helpers import SpyTool, delegation_contracts, research_contract


@pytest.fixture
def stack():
    spy = SpyTool({"hits": 1})
    harness = Harness(research_contract(), tools={"web.search": spy, "email.send": spy}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    tokens = {"researcher": authority.issue("researcher", "agent", 300)}
    approvers = {"alice": authority.issue("alice", "approver", 300)}
    server = HarnessServer(harness, authority).start()
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
    authority = TokenAuthority(Keyring.generate())
    tokens = {name: authority.issue(name, "agent", 300) for name in ("agent-a", "agent-b")}
    server = HarnessServer(harness, authority).start()
    try:
        a, b = HarnessClient(server.url, tokens["agent-a"]), HarnessClient(server.url, tokens["agent-b"])
        assert a.send_message("agent-b", "hi").allowed
        assert [m["body"] for m in b.receive()] == ["hi"]
        assert b.send_message("agent-a", "hi").status == 403
        d = a.delegate("agent-b", "database.write", {"row": 1})
        assert d.status == 403 and d.body["blocked_at"] == "recipient" and d.reason_code == "TOOL_NOT_ALLOWED"
    finally:
        server.stop()


def test_tokens_for_unknown_principals_or_wrong_roles_are_rejected():
    harness = Harness(research_contract(), audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    server = HarnessServer(harness, authority).start()
    try:
        assert HarnessClient(server.url, authority.issue("ghost", "agent", 60)).act("web.search").status == 401
        assert HarnessClient(server.url, authority.issue("alice", "agent", 60)).act("web.search").status == 401      # approver posing as agent
        assert HarnessClient(server.url, authority.issue("researcher", "approver", 60)).pending_approvals() == []     # agent posing as approver
        errors = {r["credential_error"] for r in harness.audit.query(event="authentication_failed")}
        assert errors == {"TOKEN_UNKNOWN_PRINCIPAL"}
    finally:
        server.stop()


def test_rotation_and_retirement_without_restart(tmp_path):
    keyring_path = tmp_path / "keys.json"
    keyring = Keyring.generate()
    keyring.save(keyring_path)
    harness = Harness(research_contract(), tools={"web.search": SpyTool()}, audit=AuditLog())
    server = HarnessServer(harness, TokenAuthority(keyring_path)).start()
    try:
        issuer = lambda: TokenAuthority(keyring_path)
        old = issuer().issue("researcher", "agent", 300)
        old_kid = keyring.active

        keyring.rotate()
        keyring.save(keyring_path)
        new = issuer().issue("researcher", "agent", 300)
        assert new.split(".")[1] != old_kid
        assert HarnessClient(server.url, old).act("web.search").allowed   # old key still valid during rollover
        assert HarnessClient(server.url, new).act("web.search").allowed

        keyring.retire(old_kid)
        keyring.save(keyring_path)
        assert HarnessClient(server.url, old).act("web.search").status == 401   # picked up without restart
        assert HarnessClient(server.url, new).act("web.search").allowed
    finally:
        server.stop()


def test_client_accepts_a_token_provider():
    harness = Harness(research_contract(), tools={"web.search": SpyTool()}, audit=AuditLog())
    authority = TokenAuthority(Keyring.generate())
    server = HarnessServer(harness, authority).start()
    try:
        issued = []
        client = HarnessClient(server.url, lambda: issued.append(1) or authority.issue("researcher", "agent", 30))
        assert client.act("web.search", {"q": 1}).allowed and client.act("web.search", {"q": 2}).allowed
        assert len(issued) == 2
    finally:
        server.stop()
