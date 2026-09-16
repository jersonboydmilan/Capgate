"""The boundary is structural, not cooperative.

These tests start deploy/docker-compose.yml under a throwaway project, run the
compromised agent (examples/adversarial-agent/malicious_agent.py) *inside* the
agent container, and assert on what it observed from there plus the ground
truth recorded by the real tool service and the harness.

Slow (builds images, starts containers). Opt in with:

    pytest -m docker
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("mandate_deploy_demo", ROOT / "deploy/demo.py")
demo = importlib.util.module_from_spec(_spec)
sys.modules["mandate_deploy_demo"] = demo
_spec.loader.exec_module(demo)

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not demo.docker_available(), reason="Docker with compose v2 is not available"),
]

BLOCKED = ("refused", "timeout", "dns_failed", "error:")


@pytest.fixture(scope="module")
def attack():
    stack = demo.create_stack()
    try:
        result = demo.run_attack(stack)
    finally:
        demo.destroy_stack(stack)
    return result, {check: (observed, ok) for check, observed, ok in demo.checks(result)}


def network(attack):
    return attack[0]["agent"]["isolation"]["network"]


def assert_checks(checks, prefix):
    selected = {k: v for k, v in checks.items() if k.startswith(prefix)}
    assert selected, f"no checks with prefix {prefix!r}"
    failures = {k: observed for k, (observed, ok) in selected.items() if not ok}
    assert not failures, failures


def test_agent_cannot_reach_public_internet(attack):
    net = network(attack)
    for probe in ("internet_tcp_ip", "internet_tcp_name", "internet_ipv6", "udp_dns_8_8_8_8"):
        assert net[probe].startswith(BLOCKED), (probe, net[probe])


def test_agent_cannot_reach_real_tool_directly(attack):
    result, _ = attack
    net = network(attack)
    assert net["tool_by_name"].startswith(BLOCKED) and net["tool_by_ip"].startswith(BLOCKED)
    assert net["tool_http_by_ip"] == 0  # no TCP connection at all, not an HTTP 401
    assert net["misattached_tool_same_network"] == "refused"  # even a tool wrongly placed on the agent's network
    assert result["agent"]["direct_tool_no_auth"] == 0


def test_agent_can_only_talk_to_harness(attack):
    net = network(attack)
    reachable = [name for name, outcome in net.items() if outcome in ("connected", "answered", "created") or str(outcome).startswith("resolved:")]
    assert reachable == ["harness_api"]
    assert net["harness_other_port"].startswith(BLOCKED)
    assert attack[0]["agent"]["in_contract_action"] == [200, "succeeded"]  # the policy path still works


def test_dns_and_ip_literal_blocked(attack):
    net = network(attack)
    assert net["dns_external_name"] == "dns_failed"
    for probe in ("host_gateway", "docker_bridge_gateway", "tool_by_ip"):
        assert net[probe].startswith(BLOCKED), (probe, net[probe])
    assert net["raw_socket"] == "permission_denied"


def test_egress_allowlist_installed_and_effective(attack):
    _, checks = attack
    assert checks["NET   egress allowlist installed (default DROP, only harness:8080)"][1]
    assert_checks(checks, "NET")


def test_secret_material_is_unreachable(attack):
    _, checks = attack
    assert_checks(checks, "SEC")


def test_process_is_confined(attack):
    _, checks = attack
    assert_checks(checks, "PROC")


def test_bypass_attempts_through_the_harness_still_fail(attack):
    _, checks = attack
    assert_checks(checks, "HTTP")


def test_forged_expired_revoked_and_overlong_credentials_rejected(attack):
    result, checks = attack
    assert len(result["agent"]["credentials"]) >= 9
    assert_checks(checks, "CRED")


def test_no_side_effects_from_bypass_attempts(attack):
    """Ground truth: the real tool's ledger holds exactly the one authorized action."""
    result, checks = attack
    assert_checks(checks, "PATH")
    assert len(result["side_effects"]) == 1
    assert result["side_effects"][0]["path"] == "/web.search"
    assert result["decoy_side_effects"] == []
    decisions = [r for r in result["audit"] if r.get("event") == "decision" and r.get("decision") == "allow"]
    executions = [r for r in result["audit"] if r.get("event") == "execution" and r.get("outcome") == "succeeded"]
    assert [d["action"] for d in decisions] == ["web.search"]
    assert [e["decision_id"] for e in executions] == [d["decision_id"] for d in decisions]
