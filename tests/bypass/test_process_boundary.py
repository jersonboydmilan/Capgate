"""Bypass acceptance test: a compromised agent in its own OS process, calling
raw HTTP and ignoring the SDK, cannot turn any request into an unauthorized
real-world side effect.

What this proves: with tool credentials held only by the executor, and the
tool endpoint requiring them, every route the agent has — direct tool calls,
forged identity, contract claims, self-approval, delegation — ends without a
side effect. What it does not prove: OS-level isolation between the agent
and the harness process (see docs/threat-model.md).
"""

import json
import secrets
import subprocess
import time
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from harness import AuditLog, Harness, TaskContract
from harness.identity import Keyring, TokenAuthority
from harness.server import HarnessServer
from harness.toolservice import ToolService
from harness.tools import ControlledEndpointTool

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "examples" / "adversarial-agent" / "malicious_agent.py"


@contextmanager
def start_deployment(tmp_path):
    tool_secret = secrets.token_urlsafe(32)
    tools = ToolService(tool_secret, tmp_path / "ledger.jsonl").start()
    contracts = [
        TaskContract.from_dict({
            "contract_id": "research-v1", "goal": "research", "approvers": ["alice"],
            "agents": {"researcher": {"capabilities": {"web.search": "allow", "email.send": "escalate"}}},
        }),
        TaskContract.from_dict({
            "contract_id": "admin-v1", "goal": "maintain db",
            "agents": {"db-admin": {"capabilities": {"database.write": "allow"}}},
        }),
    ]
    harness = Harness(
        contracts,
        tools={
            "web.search": ControlledEndpointTool(f"{tools.url}/web.search", tool_secret),
            "database.write": ControlledEndpointTool(f"{tools.url}/database.write", tool_secret),
        },
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )
    authority = TokenAuthority(Keyring.generate(), max_ttl_seconds=900, state=harness.state)
    agent_token = authority.issue("researcher", "agent", 600)
    revoked = authority.issue("researcher", "agent", 600)
    authority.revoke(revoked)
    lenient = TokenAuthority(authority._keyring, max_ttl_seconds=86_400)  # same key, looser issuer: verifier must still cap TTL
    extra_tokens = {
        "EXPIRED_TOKEN": authority.issue("researcher", "agent", 60, issued_at=time.time() - 3600),
        "REVOKED_TOKEN": revoked,
        "OVERLONG_TOKEN": lenient.issue("researcher", "agent", 86_400),
    }
    server = HarnessServer(harness, authority).start()
    try:
        yield {"tools": tools, "server": server, "harness": harness, "agent_token": agent_token, "extra_tokens": extra_tokens,
               "authority": authority, "tmp": tmp_path}
    finally:
        server.stop()
        tools.stop()


@pytest.fixture
def deployment(tmp_path):
    with start_deployment(tmp_path) as d:
        yield d


def agent_env(d):
    return {"PATH": "/usr/bin:/bin", "HARNESS_URL": d["server"].url, "AGENT_TOKEN": d["agent_token"], "TOOL_URL": d["tools"].url, **d["extra_tokens"]}


def run_agent(env):
    proc = subprocess.run([sys.executable, str(AGENT)], env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_compromised_agent_process_cannot_cause_unauthorized_side_effects(deployment):
    r = run_agent(agent_env(deployment))

    assert r["env_has_tool_credential"] is False
    assert r["direct_tool_no_auth"] == 401
    assert r["direct_tool_with_agent_token"] == 401
    assert r["direct_tool_guessed_token"] == 401
    assert r["harness_out_of_contract"] == [403, "TOOL_NOT_ALLOWED"]
    assert r["harness_impersonation"] == [403, "IDENTITY_MISMATCH"]
    assert r["harness_contract_claim"] == [403, "CONTRACT_MISMATCH"]
    assert r["harness_no_token"] == 401
    assert r["escalation_created"] == 202
    assert r["self_approval"] == 404
    assert r["delegation_to_privileged_agent"] == [403, "TOOL_NOT_ALLOWED"]
    assert r["in_contract_action"] == [200, "succeeded"]
    assert r["credentials"] and set(r["credentials"].values()) == {401}, r["credentials"]
    assert set(r["credentials"]) >= {"sub_swapped_to_db_admin", "expiry_extended_one_year", "forged_with_guessed_key", "expired_token", "revoked_token", "overlong_token"}

    # The ground truth: the real tool recorded exactly one side effect — the authorized one.
    effects = deployment["tools"].side_effects()
    assert [e["path"] for e in effects] == ["/web.search"]
    assert effects[0]["payload"] == {"query": "hello"}

    # And every attempt that reached the harness is in the audit trail.
    audit = deployment["harness"].audit
    audit.verify()
    reasons = {rec.get("reason_code") for rec in audit.records()}
    assert {"TOOL_NOT_ALLOWED", "IDENTITY_MISMATCH", "CONTRACT_MISMATCH", "UNAUTHENTICATED", "REQUIRES_APPROVAL", "CAPABILITY_GRANTED"} <= reasons
    errors = {rec.get("credential_error") for rec in audit.query(event="authentication_failed")}
    assert {"TOKEN_BAD_SIGNATURE", "TOKEN_EXPIRED", "TOKEN_REVOKED", "TOKEN_TTL_TOO_LONG", "TOKEN_UNKNOWN_KEY", "TOKEN_MISSING"} <= errors


def test_agent_process_cannot_reuse_escalation_after_rejection(deployment):
    import urllib.request

    server, harness = deployment["server"], deployment["harness"]
    req = urllib.request.Request(
        f"{server.url}/v1/actions",
        data=json.dumps({"action": "email.send", "arguments": {"to": "x@example.com"}}).encode(),
        headers={"Authorization": f"Bearer {deployment['agent_token']}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        approval_id = json.loads(resp.read())["approval_id"]
    harness.reject(approval_id, "alice", "not today")
    with pytest.raises(Exception):
        harness.approve(approval_id, "alice")
