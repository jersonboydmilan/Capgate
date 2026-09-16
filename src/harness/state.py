"""Authority state that must survive restarts.

  * step counters per contract and call counters per (agent, action) — budgets
  * used execution-grant ids — replay protection
  * pending and decided escalations — the human-approval queue
  * undelivered inter-agent messages
  * revoked credential ids

`MemoryStateStore` is the default for tests and simulation. `SQLiteStateStore`
persists to a file; its `transaction()` takes a database write lock, so several
harness processes on one host sharing the file make consistent budget and
replay decisions.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Protocol


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


class MemoryStateStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._steps: dict[str, int] = {}
        self._calls: dict[tuple[str, str], int] = {}
        self._grants: dict[str, float] = {}
        self._approvals: dict[str, dict[str, Any]] = {}
        self._messages: dict[str, list[dict[str, Any]]] = {}
        self._revoked: dict[str, float] = {}

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


_SCHEMA = """
CREATE TABLE IF NOT EXISTS steps     (contract_id TEXT PRIMARY KEY, n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS calls     (agent_id TEXT, action TEXT, n INTEGER NOT NULL, PRIMARY KEY (agent_id, action));
CREATE TABLE IF NOT EXISTS grants    (decision_id TEXT PRIMARY KEY, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS approvals (approval_id TEXT PRIMARY KEY, status TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages  (seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS revoked   (token_id TEXT PRIMARY KEY, expires_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS messages_recipient ON messages(recipient);
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

    def prune(self, now: float) -> None:
        """Drop grant and revocation rows that have expired; they can no longer be presented."""
        with self.transaction():
            db = self._connect()
            db.execute("DELETE FROM grants WHERE expires_at < ?", (now - 3600,))
            db.execute("DELETE FROM revoked WHERE expires_at < ?", (now - 3600,))
