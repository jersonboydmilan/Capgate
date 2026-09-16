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
