"""The SPIFFE-aware mTLS edge, in the containerised deployment.

Runs deploy/mtls/demo.py end to end (agent with a client cert -> mTLS edge ->
harness) and asserts the identity path holds: the bound token works only with
the workload's cert, forged identity headers are overwritten by the edge, a
missing client cert cannot connect, and only authorized calls reach the tool.

Slow (builds images, drives containers). Opt in with `pytest -m docker`.
"""

import importlib.util
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("capgate_mtls_demo", ROOT / "deploy/mtls/demo.py")
demo = importlib.util.module_from_spec(_spec)
sys.modules["capgate_mtls_demo"] = demo
_spec.loader.exec_module(demo)

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def result():
    if not demo.docker_available():
        pytest.skip("Docker with compose v2 is not available")
    pytest.importorskip("cryptography")
    project = f"capgate-mtls-test-{uuid.uuid4().hex[:8]}"
    certs = Path(tempfile.mkdtemp(prefix="capgate-mtls-test-", dir="/tmp" if sys.platform == "darwin" else None))
    certs.chmod(0o755)
    thumbprint = demo.mint_certs(certs)
    r = demo.run(project, certs, thumbprint)
    try:
        yield r
    finally:
        r["compose"]("--profile", "agent", "down", "-v", "--remove-orphans", check=False)


def test_every_edge_check_passes(result):
    failures = {c: o for c, o, ok in demo.checks(result) if not ok}
    assert not failures, failures


def test_only_authorized_side_effects(result):
    assert result["side_effects"] and all(e["path"] == "/web.search" for e in result["side_effects"])
    assert not any(e["path"] == "/database.write" for e in result["side_effects"])
