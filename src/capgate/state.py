"""Authority state that must survive restarts.

  * step counters per contract and call counters per (agent, action) — budgets
  * used execution-grant ids — replay protection
  * pending and decided escalations — the human-approval queue
  * undelivered inter-agent messages
  * revoked credential ids

Pick a backend with `open_state_store(url)`:

  * `memory://`                         in-process (tests, simulation)
  * `sqlite:///path/state.db` or a path one host, many processes (a file write lock)
  * `postgresql://user:pw@host/db`      many hosts (a shared, transactional backend)

All three honour the same contract: `transaction()` makes the interceptor's
read-evaluate-increment atomic, and `claim_grant` is single-use. The Postgres
store serializes state transactions with a cluster-wide advisory lock, so
several harness replicas make consistent budget, permit and approval decisions.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Protocol


def _bucket_step(tokens: float | None, last: float | None, rate: float, burst: int, now: float) -> tuple[bool, float, float]:
    """Token-bucket transition. Returns (allowed, new_tokens, retry_seconds)."""
    tokens = float(burst) if tokens is None else min(burst, tokens + max(0.0, now - (last or now)) * rate)
    if tokens >= 1:
        return True, tokens - 1, 0.0
    return False, tokens, (1 - tokens) / rate


class StateStore(Protocol):
    def transaction(self): ...
    def steps(self, contract_id: str) -> int: ...
    def add_step(self, contract_id: str) -> None: ...
    def calls(self, agent_id: str, action: str) -> int: ...
    def add_call(self, agent_id: str, action: str) -> None: ...
    def claim_grant(self, decision_id: str, expires_at: float) -> bool: ...
    def put_approval(self, approval_id: str, record: dict[str, Any]) -> None: ...
    def get_approval(self, approval_id: str) -> dict[str, Any] | None: ...
    def pending_approvals(self) -> list[dict[str, Any]]: ...
    def push_message(self, recipient: str, message: dict[str, Any]) -> None: ...
    def drain_messages(self, recipient: str) -> list[dict[str, Any]]: ...
    def revoke(self, token_id: str, expires_at: float) -> None: ...
    def is_revoked(self, token_id: str) -> bool: ...
    # shared rate limiting (multi-host); optional — LocalRateBackend is used when absent
    def rate_take(self, bucket: str, key: str, rate: float, burst: int, now: float) -> tuple[bool, float]: ...
    def rate_admit(self, bucket: str, key: str, per_minute: int, now: float) -> tuple[bool, int]: ...


class MemoryStateStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._steps: dict[str, int] = {}
        self._calls: dict[tuple[str, str], int] = {}
        self._grants: dict[str, float] = {}
        self._approvals: dict[str, dict[str, Any]] = {}
        self._messages: dict[str, list[dict[str, Any]]] = {}
        self._revoked: dict[str, float] = {}
        self._rate: dict[tuple[str, str], tuple[float, float]] = {}
        self._suppressed: dict[tuple[str, str], int] = {}

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    def steps(self, contract_id: str) -> int:
        return self._steps.get(contract_id, 0)

    def add_step(self, contract_id: str) -> None:
        with self._lock:
            self._steps[contract_id] = self.steps(contract_id) + 1

    def calls(self, agent_id: str, action: str) -> int:
        return self._calls.get((agent_id, action), 0)

    def add_call(self, agent_id: str, action: str) -> None:
        with self._lock:
            self._calls[(agent_id, action)] = self.calls(agent_id, action) + 1

    def claim_grant(self, decision_id: str, expires_at: float) -> bool:
        with self._lock:
            if decision_id in self._grants:
                return False
            self._grants[decision_id] = expires_at
            return True

    def put_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        with self._lock:
            self._approvals[approval_id] = json.loads(json.dumps(record))

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        record = self._approvals.get(approval_id)
        return json.loads(json.dumps(record)) if record else None

    def pending_approvals(self) -> list[dict[str, Any]]:
        with self._lock:
            return [json.loads(json.dumps(r)) for r in self._approvals.values() if r["status"] == "pending"]

    def push_message(self, recipient: str, message: dict[str, Any]) -> None:
        with self._lock:
            self._messages.setdefault(recipient, []).append(dict(message))

    def drain_messages(self, recipient: str) -> list[dict[str, Any]]:
        with self._lock:
            return self._messages.pop(recipient, [])

    def revoke(self, token_id: str, expires_at: float) -> None:
        with self._lock:
            self._revoked[token_id] = expires_at

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._revoked

    def rate_take(self, bucket: str, key: str, rate: float, burst: int, now: float) -> tuple[bool, float]:
        with self._lock:
            tokens, last = self._rate.get((bucket, key), (None, None))
            allowed, new_tokens, retry = _bucket_step(tokens, last, rate, burst, now)
            self._rate[(bucket, key)] = (new_tokens, now)
            return allowed, retry

    def rate_admit(self, bucket: str, key: str, per_minute: int, now: float) -> tuple[bool, int]:
        allowed, _ = self.rate_take(f"audit:{bucket}", key, per_minute / 60.0, max(per_minute, 1), now)
        with self._lock:
            k = (bucket, key)
            if not allowed:
                self._suppressed[k] = self._suppressed.get(k, 0) + 1
                return False, 0
            return True, self._suppressed.pop(k, 0)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS steps     (contract_id TEXT PRIMARY KEY, n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS calls     (agent_id TEXT, action TEXT, n INTEGER NOT NULL, PRIMARY KEY (agent_id, action));
CREATE TABLE IF NOT EXISTS grants    (decision_id TEXT PRIMARY KEY, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, status TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages  (seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS revoked   (token_id TEXT PRIMARY KEY, expires_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient);
CREATE TABLE IF NOT EXISTS rate      (bucket TEXT, key TEXT, tokens REAL NOT NULL, last REAL NOT NULL, PRIMARY KEY (bucket, key));
CREATE TABLE IF NOT EXISTS rate_suppress (bucket TEXT, key TEXT, n INTEGER NOT NULL, PRIMARY KEY (bucket, key));
"""


class SQLiteStateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._local = threading.local()
        with self._connect() as db:
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = getattr(self._local, "db", None)
        if db is None:
            db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            self._local.db = db
            self._local.depth = 0
        return db

    @contextmanager
    def transaction(self) -> Iterator[None]:
        db = self._connect()
        if self._local.depth == 0:
            db.execute("BEGIN IMMEDIATE")  # write lock: read-evaluate-increment is atomic across processes
        self._local.depth += 1
        try:
            yield
        except BaseException:
            self._local.depth -= 1
            if self._local.depth == 0:
                db.execute("ROLLBACK")
            raise
        else:
            self._local.depth -= 1
            if self._local.depth == 0:
                db.execute("COMMIT")

    def _one(self, sql: str, *args: Any) -> Any:
        row = self._connect().execute(sql, args).fetchone()
        return row[0] if row else None

    def steps(self, contract_id: str) -> int:
        return self._one("SELECT n FROM steps WHERE contract_id=?", contract_id) or 0

    def add_step(self, contract_id: str) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO steps(contract_id, n) VALUES(?, 1) ON CONFLICT(contract_id) DO UPDATE SET n = n + 1", (contract_id,)
            )

    def calls(self, agent_id: str, action: str) -> int:
        return self._one("SELECT n FROM calls WHERE agent_id=? AND action=?", agent_id, action) or 0

    def add_call(self, agent_id: str, action: str) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO calls(agent_id, action, n) VALUES(?, ?, 1) ON CONFLICT(agent_id, action) DO UPDATE SET n = n + 1",
                (agent_id, action),
            )

    def claim_grant(self, decision_id: str, expires_at: float) -> bool:
        with self.transaction():
            try:
                self._connect().execute("INSERT INTO grants(decision_id, expires_at) VALUES(?, ?)", (decision_id, expires_at))
                return True
            except sqlite3.IntegrityError:
                return False

    def put_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO approvals(approval_id, status, record) VALUES(?, ?, ?) "
                "ON CONFLICT(approval_id) DO UPDATE SET status=excluded.status, record=excluded.record",
                (approval_id, record["status"], json.dumps(record)),
            )

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        raw = self._one("SELECT record FROM approvals WHERE approval_id=?", approval_id)
        return json.loads(raw) if raw else None

    def pending_approvals(self) -> list[dict[str, Any]]:
        rows = self._connect().execute("SELECT record FROM approvals WHERE status='pending' ORDER BY rowid").fetchall()
        return [json.loads(r[0]) for r in rows]

    def push_message(self, recipient: str, message: dict[str, Any]) -> None:
        with self.transaction():
            self._connect().execute("INSERT INTO messages(recipient, message) VALUES(?, ?)", (recipient, json.dumps(message)))

    def drain_messages(self, recipient: str) -> list[dict[str, Any]]:
        with self.transaction():
            db = self._connect()
            rows = db.execute("SELECT seq, message FROM messages WHERE recipient=? ORDER BY seq", (recipient,)).fetchall()
            db.execute("DELETE FROM messages WHERE recipient=? AND seq <= ?", (recipient, rows[-1][0] if rows else -1))
            return [json.loads(m) for _, m in rows]

    def revoke(self, token_id: str, expires_at: float) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO revoked(token_id, expires_at) VALUES(?, ?) ON CONFLICT(token_id) DO NOTHING", (token_id, expires_at)
            )

    def is_revoked(self, token_id: str) -> bool:
        return self._one("SELECT 1 FROM revoked WHERE token_id=?", token_id) is not None

    def rate_take(self, bucket: str, key: str, rate: float, burst: int, now: float) -> tuple[bool, float]:
        with self.transaction():
            db = self._connect()
            row = db.execute("SELECT tokens, last FROM rate WHERE bucket=? AND key=?", (bucket, key)).fetchone()
            allowed, new_tokens, retry = _bucket_step(row[0] if row else None, row[1] if row else None, rate, burst, now)
            db.execute("INSERT INTO rate(bucket, key, tokens, last) VALUES(?, ?, ?, ?) "
                       "ON CONFLICT(bucket, key) DO UPDATE SET tokens=excluded.tokens, last=excluded.last", (bucket, key, new_tokens, now))
            return allowed, retry

    def rate_admit(self, bucket: str, key: str, per_minute: int, now: float) -> tuple[bool, int]:
        with self.transaction():
            allowed, _ = self.rate_take(f"audit:{bucket}", key, per_minute / 60.0, max(per_minute, 1), now)
            db = self._connect()
            if not allowed:
                db.execute("INSERT INTO rate_suppress(bucket, key, n) VALUES(?, ?, 1) "
                           "ON CONFLICT(bucket, key) DO UPDATE SET n = rate_suppress.n + 1", (bucket, key))
                return False, 0
            row = db.execute("SELECT n FROM rate_suppress WHERE bucket=? AND key=?", (bucket, key)).fetchone()
            db.execute("DELETE FROM rate_suppress WHERE bucket=? AND key=?", (bucket, key))
            return True, (row[0] if row else 0)

    def prune(self, now: float) -> None:
        """Drop grant and revocation rows that have expired; they can no longer be presented."""
        with self.transaction():
            db = self._connect()
            db.execute("DELETE FROM grants WHERE expires_at < ?", (now - 3600,))
            db.execute("DELETE FROM revoked WHERE expires_at < ?", (now - 3600,))


class PostgresStateStore:
    """Multi-host authority state on PostgreSQL.

    A cluster-wide advisory lock (`pg_advisory_xact_lock`) held for the duration
    of each `transaction()` serializes read-evaluate-increment and grant claims
    across every harness replica, so budgets cannot be overspent and a permit
    cannot be used twice, whichever host serves the request. This trades
    throughput for correctness — the simplest scheme that is obviously right;
    finer per-contract locking is a later optimisation.

    Requires `psycopg` (the `postgres` extra). Connections are per-thread.
    """

    _LOCK_KEY = 0x00C0_FFEE_CA96A7E5  # constant advisory-lock key shared by all replicas

    _SCHEMA = (
        "CREATE TABLE IF NOT EXISTS steps     (contract_id TEXT PRIMARY KEY, n BIGINT NOT NULL);",
        "CREATE TABLE IF NOT EXISTS calls     (agent_id TEXT, action TEXT, n BIGINT NOT NULL, PRIMARY KEY (agent_id, action));",
        "CREATE TABLE IF NOT EXISTS grants    (decision_id TEXT PRIMARY KEY, expires_at DOUBLE PRECISION NOT NULL);",
        "CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, status TEXT NOT NULL, record JSONB NOT NULL);",
        "CREATE TABLE IF NOT EXISTS messages  (seq BIGSERIAL PRIMARY KEY, recipient TEXT NOT NULL, message JSONB NOT NULL);",
        "CREATE TABLE IF NOT EXISTS revoked   (token_id TEXT PRIMARY KEY, expires_at DOUBLE PRECISION NOT NULL);",
        "CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status);",
        "CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient, seq);",
        "CREATE TABLE IF NOT EXISTS rate (bucket TEXT, key TEXT, tokens DOUBLE PRECISION NOT NULL, last DOUBLE PRECISION NOT NULL, PRIMARY KEY (bucket, key));",
        "CREATE TABLE IF NOT EXISTS rate_suppress (bucket TEXT, key TEXT, n BIGINT NOT NULL, PRIMARY KEY (bucket, key));",
    )

    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn
        self._local = threading.local()
        with self._connect() as conn, conn.transaction():
            for stmt in self._SCHEMA:
                conn.execute(stmt)

    def _connect(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            conn = self._psycopg.connect(self._dsn, autocommit=True)
            self._local.conn = conn
            self._local.depth = 0
        return conn

    @contextmanager
    def transaction(self) -> Iterator[None]:
        conn = self._connect()
        if self._local.depth == 0:
            conn.execute("BEGIN")
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (self._LOCK_KEY,))  # released at COMMIT/ROLLBACK
        self._local.depth += 1
        try:
            yield
        except BaseException:
            self._local.depth -= 1
            if self._local.depth == 0:
                conn.execute("ROLLBACK")
            raise
        else:
            self._local.depth -= 1
            if self._local.depth == 0:
                conn.execute("COMMIT")

    def _one(self, sql: str, *args: Any) -> Any:
        row = self._connect().execute(sql, args).fetchone()
        return row[0] if row else None

    def steps(self, contract_id: str) -> int:
        return self._one("SELECT n FROM steps WHERE contract_id=%s", contract_id) or 0

    def add_step(self, contract_id: str) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO steps(contract_id, n) VALUES(%s, 1) ON CONFLICT(contract_id) DO UPDATE SET n = steps.n + 1",
                (contract_id,),
            )

    def calls(self, agent_id: str, action: str) -> int:
        return self._one("SELECT n FROM calls WHERE agent_id=%s AND action=%s", agent_id, action) or 0

    def add_call(self, agent_id: str, action: str) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO calls(agent_id, action, n) VALUES(%s, %s, 1) "
                "ON CONFLICT(agent_id, action) DO UPDATE SET n = calls.n + 1",
                (agent_id, action),
            )

    def claim_grant(self, decision_id: str, expires_at: float) -> bool:
        with self.transaction():
            cur = self._connect().execute(
                "INSERT INTO grants(decision_id, expires_at) VALUES(%s, %s) ON CONFLICT(decision_id) DO NOTHING",
                (decision_id, expires_at),
            )
            return cur.rowcount == 1  # first insert wins; a replay conflicts and inserts nothing

    def put_approval(self, approval_id: str, record: dict[str, Any]) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO approvals(approval_id, status, record) VALUES(%s, %s, %s) "
                "ON CONFLICT(approval_id) DO UPDATE SET status=excluded.status, record=excluded.record",
                (approval_id, record["status"], self._psycopg.types.json.Jsonb(record)),
            )

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        return self._one("SELECT record FROM approvals WHERE approval_id=%s", approval_id)

    def pending_approvals(self) -> list[dict[str, Any]]:
        rows = self._connect().execute("SELECT record FROM approvals WHERE status='pending' ORDER BY approval_id").fetchall()
        return [r[0] for r in rows]

    def push_message(self, recipient: str, message: dict[str, Any]) -> None:
        with self.transaction():
            self._connect().execute("INSERT INTO messages(recipient, message) VALUES(%s, %s)",
                                    (recipient, self._psycopg.types.json.Jsonb(message)))

    def drain_messages(self, recipient: str) -> list[dict[str, Any]]:
        with self.transaction():
            rows = self._connect().execute(
                "DELETE FROM messages WHERE recipient=%s RETURNING message", (recipient,)
            ).fetchall()
            return [r[0] for r in rows]

    def revoke(self, token_id: str, expires_at: float) -> None:
        with self.transaction():
            self._connect().execute(
                "INSERT INTO revoked(token_id, expires_at) VALUES(%s, %s) ON CONFLICT(token_id) DO NOTHING",
                (token_id, expires_at),
            )

    def is_revoked(self, token_id: str) -> bool:
        return self._one("SELECT 1 FROM revoked WHERE token_id=%s", token_id) is not None

    def rate_take(self, bucket: str, key: str, rate: float, burst: int, now: float) -> tuple[bool, float]:
        conn = self._connect()
        with conn.transaction():  # per-row lock, no cluster-wide advisory lock: rate checks stay parallel
            server_now = float(conn.execute("SELECT extract(epoch FROM clock_timestamp())").fetchone()[0])
            row = conn.execute("SELECT tokens, last FROM rate WHERE bucket=%s AND key=%s FOR UPDATE", (bucket, key)).fetchone()
            allowed, new_tokens, retry = _bucket_step(row[0] if row else None, row[1] if row else None, rate, burst, server_now)
            conn.execute("INSERT INTO rate(bucket, key, tokens, last) VALUES(%s, %s, %s, %s) "
                         "ON CONFLICT(bucket, key) DO UPDATE SET tokens=excluded.tokens, last=excluded.last", (bucket, key, new_tokens, server_now))
            return allowed, retry

    def rate_admit(self, bucket: str, key: str, per_minute: int, now: float) -> tuple[bool, int]:
        allowed, _ = self.rate_take(f"audit:{bucket}", key, per_minute / 60.0, max(per_minute, 1), now)
        conn = self._connect()
        with conn.transaction():
            if not allowed:
                conn.execute("INSERT INTO rate_suppress(bucket, key, n) VALUES(%s, %s, 1) "
                             "ON CONFLICT(bucket, key) DO UPDATE SET n = rate_suppress.n + 1", (bucket, key))
                return False, 0
            row = conn.execute("DELETE FROM rate_suppress WHERE bucket=%s AND key=%s RETURNING n", (bucket, key)).fetchone()
            return True, (row[0] if row else 0)

    def prune(self, now: float) -> None:
        with self.transaction():
            conn = self._connect()
            conn.execute("DELETE FROM grants WHERE expires_at < %s", (now - 3600,))
            conn.execute("DELETE FROM revoked WHERE expires_at < %s", (now - 3600,))


def open_state_store(url: str | None):
    """Build a StateStore from a URL (or a bare path / None).

        None or "memory://"            -> MemoryStateStore
        "sqlite:///abs/path" or a path -> SQLiteStateStore
        "postgresql://…" / "postgres://…" -> PostgresStateStore
    """
    if url is None or url == "memory://" or url == "memory:":
        return MemoryStateStore()
    if url.startswith(("postgresql://", "postgres://")):
        return PostgresStateStore(url)
    if url.startswith("sqlite://"):
        rest = url[len("sqlite://"):]
        path = rest[1:] if rest.startswith("/") and rest[1:2] == "/" else rest.lstrip("/")
        return SQLiteStateStore(path or ":memory:")
    return SQLiteStateStore(url)  # a bare filesystem path
