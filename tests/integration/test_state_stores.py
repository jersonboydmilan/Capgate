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
