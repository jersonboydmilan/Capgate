"""capgate inspect: API behaviour, local-only protections, and the approvals round trip."""

import json
import secrets
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

import pytest

from capgate import AuditLog, Harness
from capgate.identity import Keyring, TokenAuthority
from capgate.inspect import InspectServer
from capgate.server import HarnessServer
from capgate_client import HarnessClient
from helpers import SpyTool, research_contract

ROOT = Path(__file__).resolve().parents[2]
TASK = ROOT / "examples/simulation/task.yaml"


def request(server, path, *, body=None, nonce=True, host=None):
    headers = {"Content-Type": "application/json"}
    if nonce:
        headers["X-Inspect-Nonce"] = server.nonce
    if host:
        headers["Host"] = host
    req = urllib.request.Request(server.url.rstrip("/") + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if resp.headers.get_content_type() == "application/json" else raw.decode()), resp.headers
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}"), exc.headers


@pytest.fixture
def inspect(tmp_path):
    server = InspectServer(tasks=[TASK], audit_path=tmp_path / "audit.jsonl").start()
    yield server
    server.stop()


def test_page_embeds_nonce_and_strict_csp(inspect):
    status, html, headers = request(inspect, "/", nonce=False)
    assert status == 200 and inspect.nonce in html
    csp = headers["Content-Security-Policy"]
    assert f"script-src 'nonce-{inspect.nonce}'" in csp and "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp


@pytest.mark.parametrize("path, body", [("/api/config", None), ("/api/simulate", {"task_text": "", "contracts_text": ""}), ("/api/approvals/x", {"verdict": "approve"})])
def test_api_requires_nonce(inspect, path, body):
    assert request(inspect, path, body=body, nonce=False)[0] == 403


def test_dns_rebinding_host_rejected(inspect):
    assert request(inspect, "/", nonce=False, host=f"attacker.example:{inspect.port}")[0] == 403
    assert request(inspect, "/api/config", host=f"attacker.example:{inspect.port}")[0] == 403


def test_loopback_only():
    with pytest.raises(ValueError):
        InspectServer(host="0.0.0.0")


def test_load_task_and_simulate_match_cli(inspect):
    status, task, _ = request(inspect, f"/api/task?path={quote(str(TASK))}")
    assert status == 200 and "research-v1" in task["contracts_text"]
    status, sim, _ = request(inspect, "/api/simulate", body={"task_text": task["task_text"], "contracts_text": task["contracts_text"], "base_dir": task["base_dir"]})
    assert status == 200
    assert [(r["action"], r["decision"], r["reason"]) for r in sim["rows"]] == [
        ("web.search", "ALLOW", "CAPABILITY_GRANTED"),
        ("web.fetch", "ALLOW", "CAPABILITY_GRANTED"),
        ("database.read", "DENY", "EXPLICITLY_DENIED"),
        ("agent.delegate", "ESCALATE", "REQUIRES_APPROVAL"),
        ("web.search", "ALLOW", "CAPABILITY_GRANTED"),
    ]
    assert sim["summary"] == {"allow": 3, "deny": 1, "escalate": 1}
    assert sim["rows"][2]["rule"] == "capability:deny"
    assert any(g["action"] == "database.read" and g["effect"] == "deny" for g in sim["grants"])


def test_editing_the_contract_changes_the_decision(inspect):
    _, task, _ = request(inspect, f"/api/task?path={quote(str(TASK))}")
    edited = task["contracts_text"].replace("database.read: deny", "database.read: allow")
    _, sim, _ = request(inspect, "/api/simulate", body={"task_text": task["task_text"], "contracts_text": edited, "base_dir": task["base_dir"]})
    assert sim["rows"][2]["decision"] == "ALLOW"


def test_invalid_contract_reported_inline(inspect):
    _, task, _ = request(inspect, f"/api/task?path={quote(str(TASK))}")
    status, body, _ = request(inspect, "/api/simulate", body={"task_text": task["task_text"], "contracts_text": "contract_id: x\ngoal: g\nmax_steps: 50\nagents: {r: {capabilities: {web.search: perhaps}}}"})
    assert status == 422 and "effect must be" in body["error"]


def test_explain_and_diff(inspect):
    contract = TASK.parent.joinpath("contract.yaml").read_text()
    _, r, _ = request(inspect, "/api/explain", body={"contracts_text": contract, "agent": "researcher", "action": "web.fetch", "arguments": '{"url": "http://10.0.0.1/"}'})
    assert (r["decision"], r["reason_code"], r["capability"]) == ("deny", "DOMAIN_NOT_ALLOWED", "web.fetch")
    _, r, _ = request(inspect, "/api/explain", body={"contracts_text": contract, "agent": "researcher", "action": "shell.exec", "arguments": {}})
    assert (r["reason_code"], r["rule"]) == ("TOOL_NOT_ALLOWED", "default:deny")

    widened = contract.replace("database.read: deny", "database.read: allow") + "\n"
    _, d, _ = request(inspect, "/api/diff", body={"left": contract, "right": widened})
    assert [(g["agent"], g["action"], g["status"]) for g in d["grants"]] == [("researcher", "database.read", "widened")]


def test_audit_browser_filters_and_detects_tampering(inspect, tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    harness = Harness(research_contract(), audit=log)
    harness.authorize("researcher", "web.search", {"q": 1})
    denied = harness.authorize("researcher", "database.write", {})
    harness.authorize("researcher", "email.send", {"to": "x"})

    _, view, _ = request(inspect, "/api/audit?decision=deny")
    assert view["verification"]["ok"] and view["total"] == 3
    assert [r["decision_id"] for r in view["records"]] == [denied.decision_id]
    _, view, _ = request(inspect, f"/api/audit?decision_id={denied.decision_id}")
    assert len(view["records"]) == 1

    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["decision"] = "allow"; lines[1] = json.dumps(rec)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    _, view, _ = request(inspect, "/api/audit")
    assert view["verification"] == {"ok": False, "error": "record 1: contents modified", "bad_sequence": 1}
    assert [r["_valid"] for r in view["records"]] == [True, False, False]


def test_approvals_round_trip_through_real_harness(tmp_path):
    spy = SpyTool({"sent": True})
    harness = Harness(research_contract(), tools={"email.send": spy}, audit=AuditLog(tmp_path / "audit.jsonl"))
    authority = TokenAuthority(Keyring.generate())
    api = HarnessServer(harness, authority).start()
    alice = authority.issue("alice", "approver", 600)
    inspect = InspectServer(audit_path=tmp_path / "audit.jsonl", harness_url=api.url, approver_token=lambda: alice).start()
    try:
        agent = HarnessClient(api.url, authority.issue("researcher", "agent", 600))
        keep = agent.act("email.send", {"to": "team@example.com"})
        drop = agent.act("email.send", {"to": "everyone@example.com"})
        assert keep.escalated and drop.escalated

        status, pending, _ = request(inspect, "/api/approvals")
        assert status == 200 and {a["approval_id"] for a in pending["approvals"]} == {keep.approval_id, drop.approval_id}
        assert alice not in json.dumps(pending)  # the approver token never reaches the browser

        status, result, _ = request(inspect, f"/api/approvals/{keep.approval_id}", body={"verdict": "approve", "note": "reviewed"})
        assert status == 200 and result["execution"]["status"] == "succeeded"
        status, result, _ = request(inspect, f"/api/approvals/{drop.approval_id}", body={"verdict": "reject", "note": "too broad"})
        assert status == 403 and result["reason_code"] == "APPROVAL_REJECTED"

        assert spy.calls == [{"to": "team@example.com"}]
        assert request(inspect, "/api/approvals")[1]["approvals"] == []
        _, view, _ = request(inspect, "/api/audit?event=approval")
        assert [(r["approver"], r["verdict"], r["note"]) for r in view["records"]] == [("alice", "granted", "reviewed"), ("alice", "rejected", "too broad")]
        assert request(inspect, "/api/approvals/..%2Fv1%2Factions", body={"verdict": "approve"})[0] in (404, 422)
    finally:
        inspect.stop()
        api.stop()


def test_approvals_unconfigured_is_explained(inspect):
    status, body, _ = request(inspect, "/api/approvals")
    assert status == 422 and "not configured" in body["error"]


def test_policy_view_has_no_shadowed_current_identifier():
    """Regression: refreshPolicy referenced the stale-guard current() while a local const current shadowed it."""
    html = (Path(__file__).resolve().parents[2] / "src/capgate/inspect/static/index.html").read_text()
    body = html[html.index("async function refreshPolicy"):html.index("$(\"x-run\")")]
    assert "const current =" not in body and "const selectedAgent =" in body
