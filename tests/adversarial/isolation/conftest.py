"""Fixtures that run the reference deployment (deploy/docker-compose.yml) for CI.

The stack is built and attacked once per session under a throwaway compose
project (unique container names, a free host port), so it never collides with
a stack you are running by hand. Orchestration lives in deploy/demo.py, shared
with `python deploy/demo.py`, so the CLI demo and CI cannot drift apart.

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


def pytest_collection_modifyitems(config, items):
    if demo.docker_available():
        return
    skip = pytest.mark.skip(reason="Docker with compose v2 is not available")
    for item in items:
        if "isolation" in str(item.fspath):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def isolated_stack():
    """Build images, start bootstrap/tools/harness/netguard, tear everything down (with volumes) afterwards."""
    stack = demo.create_stack()
    try:
        yield stack
    finally:
        demo.destroy_stack(stack)


@pytest.fixture(scope="session")
def attack_result(isolated_stack):
    """Run the compromised agent inside the firewalled container, once, and collect ground truth."""
    try:
        return demo.run_attack(isolated_stack)
    except Exception as exc:
        logs = isolated_stack.compose("logs", check=False).stdout[-4000:]
        pytest.fail(f"isolated deployment failed: {exc}\n--- compose logs ---\n{logs}")


@pytest.fixture(scope="session")
def run_malicious_agent(attack_result):
    """The agent's human-readable log (`[malicious] …` lines)."""
    return attack_result["agent_log"]


@pytest.fixture(scope="session")
def agent_observations(attack_result):
    """What the agent observed, as structured data."""
    return attack_result["agent"]


@pytest.fixture(scope="session")
def tool_side_effects(attack_result):
    """Ledger of the real tool service: every side effect that actually happened."""
    return attack_result["side_effects"]


@pytest.fixture(scope="session")
def harness_audit(attack_result):
    """The harness's audit trail, read from its volume after the attack."""
    return attack_result["audit"]


@pytest.fixture(scope="session")
def checks(attack_result):
    return {check: (observed, ok) for check, observed, ok in demo.checks(attack_result)}
