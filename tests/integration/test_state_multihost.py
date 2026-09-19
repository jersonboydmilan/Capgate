"""Multi-host authority state on PostgreSQL.

Starts a real Postgres in a container and proves that several harness
"replicas" sharing it make consistent decisions: a shared budget is granted
exactly N times no matter which replica serves each request, and an execution
permit issued on one replica can be used once, from any replica.

Slow (starts a container). Opt in with `pytest -m docker`.
"""

import secrets
import threading
import time
import uuid

import pytest

pytest.importorskip("psycopg")
import subprocess

from capgate import AuditLog, ExecutionRefused, Harness, ReasonCode, TaskContract
from capgate.state import PostgresStateStore
from helpers import SpyTool


def _docker() -> bool:
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=20)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = [pytest.mark.docker, pytest.mark.skipif(not _docker(), reason="Docker not available")]


@pytest.fixture(scope="module")
def dsn():
    import psycopg

    name = f"capgate-pg-{uuid.uuid4().hex[:8]}"
    password = secrets.token_hex(8)
    # publish on a random host port
    run = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "-e", f"POSTGRES_PASSWORD={password}",
         "-e", "POSTGRES_DB=capgate", "-P", "postgres:16-alpine"],
        capture_output=True, text=True,
    )
    if run.returncode != 0:
        pytest.skip(f"cannot start postgres:16-alpine: {run.stderr.strip()}")
    try:
        port = subprocess.run(["docker", "port", name, "5432/tcp"], capture_output=True, text=True, check=True).stdout.strip().rsplit(":", 1)[-1]
        url = f"postgresql://postgres:{password}@127.0.0.1:{port}/capgate"
        deadline = time.time() + 60
        while True:
            try:
                psycopg.connect(url, connect_timeout=3).close()
                break
            except Exception:
                if time.time() > deadline:
                    pytest.skip("postgres did not become ready")
                time.sleep(1)
        yield url
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def contract(max_steps):
    return TaskContract.from_dict({
        "contract_id": "shared", "goal": "g", "max_steps": max_steps,
        "agents": {"researcher": {"capabilities": {"web.search": "allow"}}},
    })


def test_postgres_passes_the_store_contract(dsn):
    store = PostgresStateStore(dsn)
    store.add_step("c"); store.add_step("c")
    assert store.steps("c") == 2 and store.steps("nope") == 0
    store.add_call("ag", "web.search")
    assert store.calls("ag", "web.search") == 1
    assert store.claim_grant("g1", 9e12) is True and store.claim_grant("g1", 9e12) is False
    store.put_approval("ap", {"status": "pending", "x": 1})
    assert [a["x"] for a in store.pending_approvals()] == [1]
    store.put_approval("ap", {"status": "decided", "x": 1})
    assert store.pending_approvals() == []
    store.push_message("bob", {"n": 0}); store.push_message("bob", {"n": 1})
    assert [m["n"] for m in store.drain_messages("bob")] == [0, 1]
    assert store.drain_messages("bob") == []
    assert store.is_revoked("t") is False
    store.revoke("t", 9e12)
    assert store.is_revoked("t") is True


def test_two_replicas_share_one_budget(dsn):
    """Two independent Harness replicas (separate connections) over one Postgres:
    a max_steps budget is granted exactly that many times in total."""
    budget = 40
    key = secrets.token_bytes(32)
    replicas = [
        Harness(contract(budget), tools={"web.search": SpyTool()}, audit=AuditLog(), state=PostgresStateStore(dsn), signing_key=key)
        for _ in range(2)
    ]
    allowed = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def worker(h):
        barrier.wait()
        for _ in range(40):
            r = h.authorize("researcher", "web.search", {"q": "x"})
            with lock:
                allowed.append(r.allowed)

    threads = [threading.Thread(target=worker, args=(replicas[i % 2],)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(allowed) == budget
    assert PostgresStateStore(dsn).steps("shared") >= budget  # every proposal counted


def test_execution_permit_is_single_use_across_replicas(dsn):
    key = secrets.token_bytes(32)
    spy_a, spy_b = SpyTool(), SpyTool()
    a = Harness(contract(1000), tools={"web.search": spy_a}, audit=AuditLog(), state=PostgresStateStore(dsn), signing_key=key)
    b = Harness(contract(1000), tools={"web.search": spy_b}, audit=AuditLog(), state=PostgresStateStore(dsn), signing_key=key)
    result = a.authorize("researcher", "web.search", {"q": "shared"})   # permit minted on replica A
    assert result.allowed
    execution = b.execute_grant(result.grant, result.request)          # ...used on replica B
    assert execution.ok and spy_b.calls == [{"q": "shared"}]
    with pytest.raises(ExecutionRefused) as refused:                    # replay on A is refused
        a.execute_grant(result.grant, result.request)
    assert refused.value.reason == "GRANT_ALREADY_USED"
    assert spy_a.calls == []
