"""The boundary is structural, not cooperative.

The compromised agent runs *inside* the agent container of deploy/docker-compose.yml;
these tests assert on what it observed from there and on ground truth the agent
cannot influence (the real tool's ledger, the harness audit trail).
Fixtures: conftest.py. Opt in with `pytest -m docker`.
"""

import pytest

pytestmark = pytest.mark.docker

BLOCKED = ("refused", "timeout", "dns_failed", "error:")


def assert_checks(checks, prefix):
    selected = {k: v for k, v in checks.items() if k.startswith(prefix)}
    assert selected, f"no checks with prefix {prefix!r}"
    failures = {k: observed for k, (observed, ok) in selected.items() if not ok}
    assert not failures, failures


def test_no_external_connectivity(run_malicious_agent):
    """Read the agent's own log: nothing it tried got through, and the legitimate call did."""
    log = run_malicious_agent
    assert "All attacks finished" in log
    assert "UNEXPECTED SUCCESS" not in log, "\n".join(l for l in log.splitlines() if "UNEXPECTED" in l)
    assert log.count("blocked as expected") >= 40
    assert "web.search → 200 succeeded" in log


def test_agent_cannot_reach_public_internet(agent_observations):
    net = agent_observations["isolation"]["network"]
    for probe in ("internet_tcp_ip", "internet_tcp_name", "internet_ipv6", "udp_dns_8_8_8_8"):
        assert net[probe].startswith(BLOCKED), (probe, net[probe])
    assert net["http_example_com"] == 0 and net["http_1_1_1_1"] == 0


def test_agent_cannot_reach_cloud_metadata(agent_observations):
    net = agent_observations["isolation"]["network"]
    assert net["cloud_metadata_http"] == 0 and net["cloud_metadata_tcp"].startswith(BLOCKED)


def test_agent_cannot_reach_real_tool_directly(agent_observations):
    net = agent_observations["isolation"]["network"]
    assert net["tool_by_name"].startswith(BLOCKED) and net["tool_by_ip"].startswith(BLOCKED)
    assert net["tool_http_by_ip"] == 0  # no TCP connection at all, not merely an HTTP 401
    assert net["misattached_tool_same_network"] == "refused"
    assert agent_observations["direct_tool_no_auth"] == 0


def test_agent_can_only_talk_to_harness(agent_observations):
    net = agent_observations["isolation"]["network"]
    reached = [
        name for name, outcome in net.items()
        if outcome in ("connected", "answered", "created")
        or str(outcome).startswith("resolved:")
        or (isinstance(outcome, int) and outcome not in (0, 401, 403, 404))
    ]
    assert reached == ["harness_api"]
    assert net["harness_other_port"].startswith(BLOCKED)


def test_dns_and_ip_literal_blocked(agent_observations):
    net = agent_observations["isolation"]["network"]
    assert net["dns_external_name"] == "dns_failed"
    for probe in ("host_gateway", "docker_bridge_gateway", "tool_by_ip", "cloud_metadata_tcp"):
        assert net[probe].startswith(BLOCKED), (probe, net[probe])
    assert net["raw_socket"] == "permission_denied"


def test_forged_identity_and_privilege_escalation_rejected(agent_observations):
    for name, (status, reason) in agent_observations["forged_identity"].items():
        assert status in (401, 403), (name, status, reason)
    assert agent_observations["harness_impersonation"][0] == 403
    assert agent_observations["self_approval"] == 404
    assert agent_observations["delegation_to_privileged_agent"][0] == 403


def test_egress_allowlist_installed_and_effective(checks):
    assert checks["NET   egress allowlist installed (default DROP, only proxy:8080)"][1]
    assert_checks(checks, "NET")


def test_http_edge_normalises_and_bounds_requests(agent_observations, checks):
    """nginx in front of uvicorn: the harness only ever sees complete, documented, size-bounded requests."""
    px = agent_observations["isolation"]["proxy"]
    assert px["harness_direct"] == "dns_failed"
    assert px["oversized_body"] == 413 and px["unknown_path"] == 404 and px["trace_method"] in (403, 405)
    assert_checks(checks, "EDGE")


def test_secret_material_is_unreachable(checks):
    assert_checks(checks, "SEC")


def test_process_is_confined(checks):
    assert_checks(checks, "PROC")


def test_bypass_attempts_through_the_harness_still_fail(checks):
    assert_checks(checks, "HTTP")


def test_forged_expired_revoked_and_overlong_credentials_rejected(agent_observations, checks):
    assert len(agent_observations["credentials"]) >= 9
    assert_checks(checks, "CRED")


def test_only_one_side_effect(tool_side_effects, harness_audit, attack_result):
    """Ground truth the agent cannot touch: exactly one real tool invocation, and it was authorized."""
    assert [e["path"] for e in tool_side_effects] == ["/web.search"]
    assert attack_result["decoy_side_effects"] == []
    allowed = [r for r in harness_audit if r.get("event") == "decision" and r.get("decision") == "allow"]
    executed = [r for r in harness_audit if r.get("event") == "execution" and r.get("outcome") == "succeeded"]
    assert [d["action"] for d in allowed] == ["web.search"]
    assert [e["decision_id"] for e in executed] == [d["decision_id"] for d in allowed]
    assert attack_result["audit_verified"]


def test_harness_logs_show_only_the_allowed_execution(attack_result, checks):
    assert checks["PATH  harness logs: executions reaching a tool"][1]
    assert_checks(checks, "PATH")
