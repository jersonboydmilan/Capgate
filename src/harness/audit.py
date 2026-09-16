"""Structured, hash-chained audit trail.

Records describe decisions and outcomes, never model reasoning. Each record
carries the hash of the previous one, so deletion, reordering or edits are
detectable with `verify()`. Writes fail closed: if a record cannot be
persisted, the exception propagates and the action does not proceed.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Iterable

from .request import canonical_json, sha256_hex
from .timeutil import utc_now

GENESIS = "sha256:" + "0" * 64


class AuditIntegrityError(RuntimeError):
    pass


class AuditLog:
    def __init__(self, path: str | Path | None = None, *, include_arguments: bool = True, fsync: bool = False) -> None:
        self.path = Path(path) if path else None
        self.include_arguments = include_arguments
        self._fsync = fsync
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._last_hash = GENESIS
        if self.path and self.path.exists():
            self._records = _read_jsonl(self.path)
            verify_chain(self._records)  # never extend a chain that has been tampered with
            if self._records:
                self._last_hash = self._records[-1]["hash"]

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            body = {
                "record_id": str(uuid.uuid4()),
                "sequence": len(self._records),
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
            self._records.append(body)
            self._last_hash = body["hash"]
            return dict(body)

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._records]

    def query(self, **filters: Any) -> list[dict[str, Any]]:
        """Exact-match filter, e.g. query(agent_id="b", decision="deny")."""
        return [r for r in self.records() if all(r.get(k) == v for k, v in filters.items())]

    def for_decision(self, decision_id: str) -> list[dict[str, Any]]:
        return self.query(decision_id=decision_id)

    def verify(self) -> bool:
        verify_chain(self.records())
        return True

    def __len__(self) -> int:
        return len(self._records)


def _hash_record(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return "sha256:" + sha256_hex(canonical_json(body))


def verify_chain(records: Iterable[dict[str, Any]]) -> None:
    prev = GENESIS
    for index, record in enumerate(records):
        if record.get("sequence") != index:
            raise AuditIntegrityError(f"record {index}: sequence gap or reordering")
        if record.get("prev_hash") != prev:
            raise AuditIntegrityError(f"record {index}: chain broken (prev_hash mismatch)")
        if record.get("hash") != _hash_record(record):
            raise AuditIntegrityError(f"record {index}: contents modified")
        prev = record["hash"]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                records.append(json.loads(line))
    return records


def load_audit(path: str | Path, *, verify: bool = True) -> list[dict[str, Any]]:
    records = _read_jsonl(Path(path))
    if verify:
        verify_chain(records)
    return records
