"""The same boundary, with the untrusted agent under gVisor (runsc).

This brings up the reference deployment with the gVisor overlay
(deploy/gvisor/docker-compose.gvisor.yml), so the agent container runs under a
user-space kernel instead of sharing the host kernel. It then asserts two things
the plain-runc suite cannot:

  1. the agent's OCI runtime really is ``runsc`` — a silent fall back to runc
     would make "gVisor tested" a false claim; and
  2. every boundary check that holds on runc still holds on gVisor — in
     particular, netguard's iptables egress allowlist still governs the gVisor
     container, whose own network stack joins netguard's (runc-owned) network
     namespace.

Skips unless both Docker and the runsc runtime are available. Opt in with
``pytest -m gvisor``; it is also marked ``docker`` so the default suite
(``-m 'not docker'``) never tries to start containers.

Fixtures here are independent of conftest.py's runc stack: this module builds and
tears down its own gVisor stack once per session.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

# Load deploy/demo.py the same way the package conftest does, without depending on
# import order (self-contained: reuses the already-loaded module if present).
ROOT = Path(__file__).resolve().parents[3]
if "mandate_deploy_demo" in sys.modules:
    demo = sys.modules["mandate_deploy_demo"]
else:
    _spec = importlib.util.spec_from_file_location("mandate_deploy_demo", ROOT / "deploy/demo.py")
    demo = importlib.util.module_from_spec(_spec)
    sys.modules["mandate_deploy_demo"] = demo
    _spec.loader.exec_module(demo)

pytestmark = [pytest.mark.docker, pytest.mark.gvisor]


@pytest.fixture(scope="session", autouse=True)
def _require_runsc():
    if not demo.docker_available():
        pytest.skip("Docker with compose v2 is not available")
    if not demo.runsc_available():
        pytest.skip("the gVisor (runsc) runtime is not registered in the Docker daemon")


@pytest.fixture(scope="session")
def gvisor_stack(_require_runsc):
    stack = demo.create_stack(gvisor=True)
    try:
        yield stack
    finally:
        demo.destroy_stack(stack)


@pytest.fixture(scope="session")
def gvisor_attack(gvisor_stack):
    try:
        return gvisor_stack.compose, demo.run_attack(gvisor_stack), gvisor_stack
    except Exception as exc:
        logs = gvisor_stack.compose("logs", check=False).stdout[-4000:]
        pytest.fail(f"gVisor deployment failed: {exc}\n--- compose logs ---\n{logs}")


def test_agent_runs_under_runsc(gvisor_attack):
    """No silent fall back to runc: the agent container's runtime is gVisor."""
    _, _, stack = gvisor_attack
    assert stack.service_runtime("agent") == "runsc"


def test_every_boundary_check_still_holds_under_gvisor(gvisor_attack):
    """The full adversarial check set, re-run against the gVisor stack."""
    _, result, _ = gvisor_attack
    failures = {check: observed for check, observed, ok in demo.checks(result) if not ok}
    assert not failures, failures


def test_egress_allowlist_governs_the_gvisor_container(gvisor_attack):
    """The one genuinely new question: netguard's iptables still confine gVisor's netstack."""
    _, result, _ = gvisor_attack
    net = result["agent"]["isolation"]["network"]
    blocked = ("refused", "timeout", "dns_failed", "error:")
    # reachable only through the harness API; the decoy on the agent's own network stays refused
    assert net["harness_api"] == "connected"
    assert net["misattached_tool_same_network"] == "refused"
    for probe in ("internet_tcp_ip", "tool_by_ip", "cloud_metadata_tcp", "harness_other_port"):
        assert str(net[probe]).startswith(blocked), (probe, net[probe])
    assert result["side_effects"] and [e["path"] for e in result["side_effects"]] == ["/web.search"]
