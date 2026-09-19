"""The StateStore contract, checked against every backend.

Memory and SQLite run everywhere. Postgres (multi-host) runs when
CAPGATE_TEST_PG_DSN is set, and in the docker multi-host test.
"""

import os
import threading

import pytest

from capgate.state import MemoryStateStore, SQLiteStateStore, open_state_store


def sqlite_store(tmp_path):
    return SQLiteStateStore(tmp_path / "state.db")


STORES = [("memory", lambda tmp: MemoryStateStore()), ("sqlite", sqlite_store)]
if os.environ.get("CAPGATE_TEST_PG_DSN"):
    from capgate.state import PostgresStateStore

    STORES.append(("postgres", lambda tmp: PostgresStateStore(os.environ["CAPGATE_TEST_PG_DSN"])))


@pytest.fixture(params=[s[1] for s in STORES], ids=[s[0] for s in STORES])
def store(request, tmp_path):
    return request.param(tmp_path)


def test_step_and_call_counters(store):
    assert store.steps("c") == 0
    for _ in range(3):
        store.add_step("c")
    assert store.steps("c") == 3 and store.steps("other") == 0
    store.add_call("agent", "web.search")
    store.add_call("agent", "web.search")
    assert store.calls("agent", "web.search") == 2 and store.calls("agent", "web.fetch") == 0


def test_grant_is_single_use(store):
    assert store.claim_grant("d1", 9e12) is True
    assert store.claim_grant("d1", 9e12) is False
    assert store.claim_grant("d2", 9e12) is True


def test_approvals_roundtrip_and_pending_filter(store):
    store.put_approval("a1", {"status": "pending", "x": 1})
    store.put_approval("a2", {"status": "pending", "x": 2})
    store.put_approval("a2", {"status": "decided", "x": 2})   # overwrite
    assert store.get_approval("a1") == {"status": "pending", "x": 1}
    assert [a["x"] for a in store.pending_approvals()] == [1]
    assert store.get_approval("missing") is None


def test_messages_are_fifo_and_drain_once(store):
    for i in range(3):
        store.push_message("bob", {"n": i})
    store.push_message("alice", {"n": 99})
    assert [m["n"] for m in store.drain_messages("bob")] == [0, 1, 2]
    assert store.drain_messages("bob") == []
    assert [m["n"] for m in store.drain_messages("alice")] == [99]


def test_revocation(store):
    assert store.is_revoked("t") is False
    store.revoke("t", 9e12)
    assert store.is_revoked("t") is True


def test_transaction_makes_read_increment_atomic(store):
    """The budget pattern: read-under-transaction then increment, hammered by many threads,
    grants a limited resource exactly N times."""
    limit, workers = 20, 8
    granted = []
    lock = threading.Lock()
    barrier = threading.Barrier(workers)

    def worker():
        barrier.wait()
        for _ in range(50):
            with store.transaction():
                if store.steps("budget") < limit:
                    store.add_step("budget")
                    with lock:
                        granted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert store.steps("budget") == limit
    assert len(granted) == limit


# --- shared rate limiting across instances sharing one store ---

def test_shared_rate_limit_across_instances(tmp_path):
    """Two RateLimiter instances (two 'replicas') sharing one store enforce one budget."""
    from capgate.ratelimit import RateLimitConfig, RateLimiter

    store = SQLiteStateStore(tmp_path / "rl.db")
    clock = [1000.0]
    cfg = RateLimitConfig(client_rate=1, client_burst=5, shared=True)
    a = RateLimiter(cfg, clock=lambda: clock[0], store=store)
    b = RateLimiter(cfg, clock=lambda: clock[0], store=store)
    allowed = sum((a if i % 2 else b).client("1.2.3.4")[0] for i in range(12))
    assert allowed == 5                                   # shared burst, not 5 per replica
    assert b.client("9.9.9.9")[0] is True                 # a different key is independent


def test_shared_audit_sampler_across_instances(tmp_path):
    from capgate.ratelimit import RateLimitConfig, RateLimiter

    store = SQLiteStateStore(tmp_path / "rl.db")
    clock = [1000.0]
    cfg = RateLimitConfig(auth_failure_audit_per_minute=2, shared=True)
    a = RateLimiter(cfg, clock=lambda: clock[0], store=store)
    b = RateLimiter(cfg, clock=lambda: clock[0], store=store)
    verdicts = [(a if i % 2 else b).audit_auth_failure("ip") for i in range(4)]
    assert [v[0] for v in verdicts] == [True, True, False, False]   # 2/min shared
    clock[0] += 60
    record, suppressed = a.audit_auth_failure("ip")
    assert record is True and suppressed == 2                        # the flood is counted


def test_shared_config_flag_parsed():
    from capgate.ratelimit import RateLimitConfig

    assert RateLimitConfig.from_mapping({"shared": True, "client_rate": 5}).shared is True
    assert RateLimitConfig().shared is False


def test_unshared_limiter_needs_no_store():
    from capgate.ratelimit import RateLimitConfig, RateLimiter

    rl = RateLimiter(RateLimitConfig(client_rate=1, client_burst=2))   # no store
    assert [rl.client("x")[0] for _ in range(3)] == [True, True, False]
