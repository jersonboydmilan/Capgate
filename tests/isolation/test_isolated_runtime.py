"""Acceptance tests for the reference isolated runtime (deploy/isolated).

Slow (builds images, starts containers). Opt in with:

    pytest -m docker
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("isolated_demo", ROOT / "deploy/isolated/demo.py")
demo = importlib.util.module_from_spec(spec)
sys.modules["isolated_demo"] = demo
spec.loader.exec_module(demo)

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(not demo.docker_available(), reason="Docker with compose v2 is not available"),
]


@pytest.fixture(scope="module")
def attack():
    stack = demo.create_stack()
    try:
        result = demo.run_attack(stack)
    finally:
        demo.destroy_stack(stack)
    return result, {check: (observed, ok) for check, observed, ok in demo.checks(result)}


def assert_checks(checks, prefix):
    selected = {k: v for k, v in checks.items() if k.startswith(prefix)}
    assert selected, f"no checks with prefix {prefix!r}"
    failures = {k: observed for k, (observed, ok) in selected.items() if not ok}
    assert not failures, failures


def test_raw_network_access_to_real_tools_fails(attack):
    """Compromised agent ignoring the SDK: raw TCP/HTTP to the tool endpoint is blocked by the network."""
    result, checks = attack
    net = result["agent"]["isolation"]["network"]
    assert net["tool_by_ip"] != "connected" and net["tool_by_name"] != "connected"
    assert result["agent"]["direct_tool_no_auth"] == 0  # connection-level failure, not an HTTP 401
    assert_checks(checks, "NET")


def test_no_egress_except_harness(attack):
    result, checks = attack
    net = result["agent"]["isolation"]["network"]
    reachable = [name for name, outcome in net.items() if outcome in ("connected", "answered", "created") or str(outcome).startswith("resolved:")]
    assert reachable == ["harness_api"]


def test_secret_material_is_unreachable(attack):
    _, checks = attack
    assert_checks(checks, "SEC")


def test_process_is_confined(attack):
    _, checks = attack
    assert_checks(checks, "PROC")


def test_bypass_attempts_through_the_harness_still_fail(attack):
    _, checks = attack
    assert_checks(checks, "HTTP")


def test_only_side_effect_path_is_authorize_permit_execute(attack):
    result, checks = attack
    assert_checks(checks, "PATH")
    decisions = [r for r in result["audit"] if r.get("event") == "decision" and r.get("decision") == "allow"]
    executions = [r for r in result["audit"] if r.get("event") == "execution" and r.get("outcome") == "succeeded"]
    assert [d["action"] for d in decisions] == ["web.search"]
    assert [e["decision_id"] for e in executions] == [d["decision_id"] for d in decisions]
    assert len(result["side_effects"]) == len(executions) == 1
