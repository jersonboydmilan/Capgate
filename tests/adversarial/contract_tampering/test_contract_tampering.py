from capgate import AuditLog, Harness, ReasonCode, load_contract
from helpers import FakeClock


CONTRACT = """
contract_id: research-v1
goal: research X
max_steps: 50
agents:
  researcher:
    capabilities:
      web.search: allow
"""


def test_editing_contract_file_after_load_changes_nothing(tmp_path):
    path = tmp_path / "contract.yaml"
    path.write_text(CONTRACT)
    harness = Harness(load_contract(path), clock=FakeClock())
    original_hash = harness.contract_for("researcher").content_hash

    path.write_text(CONTRACT + "      database.write: allow\n")  # attacker with file write access

    result = harness.authorize("researcher", "database.write")
    assert result.denied and result.reason_code is ReasonCode.TOOL_NOT_ALLOWED
    assert result.decision.contract_hash == original_hash


def test_every_decision_records_the_contract_hash():
    audit = AuditLog()
    harness = Harness(load_contract_from_text(CONTRACT), audit=audit, clock=FakeClock())
    harness.authorize("researcher", "web.search")
    harness.authorize("researcher", "database.write")
    expected = harness.contract_for("researcher").content_hash
    assert {r["contract_hash"] for r in audit.query(event="decision")} == {expected}


def test_contracts_view_is_a_copy():
    harness = Harness(load_contract_from_text(CONTRACT), clock=FakeClock())
    harness.contracts.clear()
    assert harness.authorize("researcher", "web.search").allowed


def test_agent_cannot_be_bound_to_two_contracts():
    import pytest
    from capgate import ContractError, TaskContract

    a = TaskContract.from_dict({"contract_id": "a", "goal": "g", "max_steps": 50, "agent": "x", "allowed_tools": ["web.search"]})
    b = TaskContract.from_dict({"contract_id": "b", "goal": "g", "max_steps": 50, "agent": "x", "allowed_tools": ["database.write"]})
    with pytest.raises(ContractError, match="exactly one contract"):
        Harness([a, b])


def load_contract_from_text(text):
    import yaml
    from capgate import TaskContract

    return TaskContract.from_dict(yaml.safe_load(text))
