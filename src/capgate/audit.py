"""Structured, hash-chained audit trail.

Records describe decisions and outcomes, never model reasoning. Each record
carries the hash of the previous one, so deletion, reordering or edits are
detectable with `verify()`. Writes fail closed: if a record cannot be
persisted, the exception propagates and the action does not proceed.

With a `path`, records are streamed to disk and not kept in memory: a
long-running harness holds only the chain head (sequence and last hash).
Reads (`records`, `query`, `for_decision`) scan the file. Without a path,
records are kept in memory (tests, simulation).
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator

from .request import canonical_json, sha256_hex
from .timeutil import utc_now

GENESIS = "sha256:" + "0" * 64


class AuditIntegrityError(RuntimeError):
    pass


class AuditLog:
    def __init__(self, path: str | Path | None = None, *, include_arguments: bool = True, fsync: bool = False, echo: Any = None) -> None:
        """`echo`: optional text stream that receives a one-line summary of every record (e.g. container logs)."""
        self.path = Path(path) if path else None
        self._echo = echo
        self.include_arguments = include_arguments
        self._fsync = fsync
        self._lock = threading.Lock()
        self._memory: list[dict[str, Any]] = []
        self._count = 0
        self._last_hash = GENESIS
        if self.path and self.path.exists():
            # Never extend a chain that has been tampered with. Streams the file: constant memory.
            self._count, self._last_hash = verify_chain(iter_records(self.path))

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            body = {
                "record_id": str(uuid.uuid4()),
                "sequence": self._count,
                "timestamp": utc_now().isoformat(),
                "event": event,
                **fields,
                "prev_hash": self._last_hash,
            }
            body["hash"] = _hash_record(body)
            line = canonical_json(body)
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    if self._fsync:
                        os.fsync(fh.fileno())
            else:
                self._memory.append(body)
            self._count += 1
            self._last_hash = body["hash"]
            if self._echo is not None:
                keys = ("agent_id", "action", "decision", "reason_code", "credential_error", "outcome")
                summary = " ".join(f"{k}={body[k]}" for k in keys if body.get(k) is not None)
                print(f"audit {body['sequence']:>5} {event:<22} {summary}", file=self._echo, flush=True)
            return dict(body)

    def iter(self) -> Iterator[dict[str, Any]]:
        if self.path:
            if self.path.exists():
                yield from iter_records(self.path)
            return
        with self._lock:
            snapshot = list(self._memory)
        for record in snapshot:
            yield dict(record)

    def records(self) -> list[dict[str, Any]]:
        return list(self.iter())

    def query(self, **filters: Any) -> list[dict[str, Any]]:
        """Exact-match filter, e.g. query(agent_id="b", decision="deny")."""
        return [r for r in self.iter() if all(r.get(k) == v for k, v in filters.items())]

    def for_decision(self, decision_id: str) -> list[dict[str, Any]]:
        return self.query(decision_id=decision_id)

    def verify(self) -> bool:
        verify_chain(self.iter())
        return True

    def __len__(self) -> int:
        return self._count


def _hash_record(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return "sha256:" + sha256_hex(canonical_json(body))


def verify_chain(records: Iterable[dict[str, Any]]) -> tuple[int, str]:
    """Verify a chain; return (record count, last hash). Raises AuditIntegrityError at the first bad record."""
    prev = GENESIS
    count = 0
    for index, record in enumerate(records):
        if record.get("sequence") != index:
            raise AuditIntegrityError(f"record {index}: sequence gap or reordering")
        if record.get("prev_hash") != prev:
            raise AuditIntegrityError(f"record {index}: chain broken (prev_hash mismatch)")
        if record.get("hash") != _hash_record(record):
            raise AuditIntegrityError(f"record {index}: contents modified")
        prev = record["hash"]
        count = index + 1
    return count, prev


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as fh:
        for number, line in enumerate(fh, start=1):
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    raise AuditIntegrityError(f"line {number}: not valid JSON") from None


def load_audit(path: str | Path, *, verify: bool = True) -> list[dict[str, Any]]:
    records = list(iter_records(Path(path)))
    if verify:
        verify_chain(records)
    return records


class PostgresAuditSink:
    """A shared, tamper-evident audit trail for many harness replicas.

    Every replica appends to one Postgres table under its own `stream_id`, and
    keeps its own hash chain within that stream. There is no cross-replica lock:
    a replica only ever extends its own stream, so appends never contend, yet the
    whole fleet's decisions are queryable from one place. `verify()` checks each
    stream's chain independently — tampering with any record breaks its stream.

    Drop-in for `AuditLog` where the harness writes (record/query/verify/…).
    Requires `psycopg` (the `postgres` extra).
    """

    _SCHEMA = (
        "CREATE TABLE IF NOT EXISTS audit ("
        " stream_id TEXT NOT NULL, sequence BIGINT NOT NULL, event TEXT NOT NULL,"
        " ts TIMESTAMPTZ NOT NULL DEFAULT now(), hash TEXT NOT NULL, record JSONB NOT NULL,"
        " PRIMARY KEY (stream_id, sequence));",
        "CREATE INDEX IF NOT EXISTS audit_decision ON audit ((record->>'decision_id'));",
        "CREATE INDEX IF NOT EXISTS audit_event ON audit (event);",
    )

    def __init__(self, dsn: str, *, stream_id: str, include_arguments: bool = True, echo: Any = None) -> None:
        import psycopg

        self._psycopg = psycopg
        self.dsn = dsn
        self.stream_id = stream_id
        self.include_arguments = include_arguments
        self._echo = echo
        self._lock = threading.Lock()
        self._conn = psycopg.connect(dsn, autocommit=True)
        with self._conn.transaction():
            for stmt in self._SCHEMA:
                self._conn.execute(stmt)
        # resume this replica's own chain (verify its tail), so a restart continues it
        self._count, self._last_hash = verify_chain(self._iter_stream(self.stream_id))

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            body = {
                "record_id": str(uuid.uuid4()),
                "stream_id": self.stream_id,
                "sequence": self._count,
                "timestamp": utc_now().isoformat(),
                "event": event,
                **fields,
                "prev_hash": self._last_hash,
            }
            body["hash"] = _hash_record(body)
            self._conn.execute(
                "INSERT INTO audit(stream_id, sequence, event, hash, record) VALUES(%s, %s, %s, %s, %s)",
                (self.stream_id, self._count, event, body["hash"], self._psycopg.types.json.Jsonb(body)),
            )
            self._count += 1
            self._last_hash = body["hash"]
            if self._echo is not None:
                keys = ("agent_id", "action", "decision", "reason_code", "credential_error", "outcome")
                summary = " ".join(f"{k}={body[k]}" for k in keys if body.get(k) is not None)
                print(f"audit[{self.stream_id}] {body['sequence']:>5} {event:<22} {summary}", file=self._echo, flush=True)
            return dict(body)

    def _iter_stream(self, stream_id: str) -> Iterator[dict[str, Any]]:
        cur = self._conn.execute("SELECT record FROM audit WHERE stream_id=%s ORDER BY sequence", (stream_id,))
        for (rec,) in cur:
            yield rec

    def _stream_ids(self) -> list[str]:
        return [r[0] for r in self._conn.execute("SELECT DISTINCT stream_id FROM audit ORDER BY stream_id").fetchall()]

    def iter(self) -> Iterator[dict[str, Any]]:
        # fleet order: by stream, then sequence within stream (each stream is a chain)
        for (rec,) in self._conn.execute("SELECT record FROM audit ORDER BY stream_id, sequence").fetchall():
            yield rec

    def records(self) -> list[dict[str, Any]]:
        return list(self.iter())

    def query(self, **filters: Any) -> list[dict[str, Any]]:
        return [r for r in self.iter() if all(r.get(k) == v for k, v in filters.items())]

    def for_decision(self, decision_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT record FROM audit WHERE record->>'decision_id'=%s ORDER BY stream_id, sequence", (decision_id,)
        ).fetchall()
        return [r[0] for r in rows]

    def verify(self) -> bool:
        for stream_id in self._stream_ids():
            verify_chain(self._iter_stream(stream_id))  # each replica's chain, independently
        return True

    def __len__(self) -> int:
        return self._conn.execute("SELECT count(*) FROM audit").fetchone()[0]


def open_audit(target: str | None, *, stream_id: str | None = None, include_arguments: bool = True, echo: Any = None, fsync: bool = False):
    """Build an audit sink from a target.

        None / a path / "sqlite is n/a here" -> AuditLog (JSONL file or in-memory)
        "postgresql://…" / "postgres://…"     -> PostgresAuditSink (shared, per-replica streams)
    """
    if isinstance(target, str) and target.startswith(("postgresql://", "postgres://")):
        import os
        import socket

        sid = stream_id or f"{socket.gethostname()}-{os.getpid()}"
        return PostgresAuditSink(target, stream_id=sid, include_arguments=include_arguments, echo=echo)
    return AuditLog(target, include_arguments=include_arguments, echo=echo, fsync=fsync)
