import json

import pytest

from harness import AuditIntegrityError, AuditLog, load_audit


def test_hash_chain_verifies_and_persists(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.record("decision", decision_id=str(i), decision="allow")
    assert log.verify()
    assert len(load_audit(path)) == 5

    reopened = AuditLog(path)
    reopened.record("decision", decision_id="5", decision="deny")
    assert len(load_audit(path)) == 6


@pytest.mark.parametrize("attack", ["edit", "delete", "reorder"])
def test_tampering_is_detected(tmp_path, attack):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.record("decision", decision_id=str(i), decision="deny")
    lines = path.read_text().splitlines()
    if attack == "edit":
        record = json.loads(lines[1])
        record["decision"] = "allow"
        lines[1] = json.dumps(record)
    elif attack == "delete":
        del lines[2]
    else:
        lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditIntegrityError):
        load_audit(path)
    with pytest.raises(AuditIntegrityError):
        AuditLog(path)  # refuses to extend a tampered chain


def test_write_failure_propagates(tmp_path):
    log = AuditLog(tmp_path / "missing-dir" / "audit.jsonl")
    with pytest.raises(OSError):
        log.record("decision", decision_id="x")
