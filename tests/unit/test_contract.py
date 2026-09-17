import pytest

from capgate import ContractError, TaskContract, load_contracts
from capgate.capability import Effect
from helpers import research_contract


def test_shorthand_form_matches_spec_example():
    contract = TaskContract.from_dict({
        "contract_id": "research-v1",
        "goal": "research X",
        "agent": "researcher",
        "allowed_tools": ["web.search", "web.fetch"],
        "max_steps": 20,
    })
    caps = contract.capabilities_for("researcher")
    assert set(caps) == {"web.search", "web.fetch"}
    assert all(c.effect is Effect.ALLOW for c in caps.values())


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"allowed_tool": ["x"]}, "unknown contract fields"),
        ({"max_steps": None}, "max_steps is required"),
        ({"max_steps": 0}, "max_steps"),
        ({"max_steps": True}, "max_steps"),
        ({"agents": {}}, "at least one agent"),
        ({"agents": {"r": {"capabilities": {"web.search": True}}}}, "not a boolean"),
        ({"agents": {"r": {"capabilities": {"web.search": "permit"}}}}, "effect must be"),
        ({"agents": {"r": {"capabilities": {"web.*": "allow"}}}}, "invalid action name"),
        ({"agents": {"r": {"capabilities": {"contract.update": "allow"}}}}, "reserved"),
        ({"agents": {"r": {"capabilities": {"harness.approve": "allow"}}}}, "reserved"),
        ({"agents": {"r": {"capabilities": {"web.fetch": {"effect": "allow", "constraints": {"allowed_domain": ["a"]}}}}}}, "unknown constraints"),
        ({"agents": {"r": {"capabilities": {"agent.message": "allow"}}}}, "allowed_targets"),
        ({"agents": {"r": {"capabilities": {"agent.delegate": {"effect": "allow", "constraints": {"allowed_targets": ["b"]}}}}}}, "allowed_actions"),
        ({"approvers": ["researcher"]}, "both an agent and an approver"),
        ({"expires_at": "2026-01-01T00:00:00"}, "timezone"),
    ],
)
def test_invalid_contracts_fail_closed(mutation, message):
    base = {"contract_id": "c1", "goal": "g", "max_steps": 50, "agents": {"researcher": {"capabilities": {"web.search": "allow"}}}}
    base.update(mutation)
    with pytest.raises(ContractError, match=message):
        TaskContract.from_dict(base)


def test_contract_is_immutable():
    contract = research_contract()
    with pytest.raises(Exception):
        contract.max_steps = 1000  # type: ignore[misc]
    with pytest.raises(TypeError):
        contract.agents["researcher"].capabilities["database.write"] = "allow"  # type: ignore[index]
    with pytest.raises(TypeError):
        contract.agents["intruder"] = None  # type: ignore[index]


def test_content_hash_is_stable_and_sensitive():
    assert research_contract().content_hash == research_contract().content_hash
    assert research_contract().content_hash != research_contract(max_steps=21).content_hash


def test_multi_document_yaml(tmp_path):
    path = tmp_path / "contracts.yaml"
    path.write_text(
        "contract_id: a\ngoal: g\nmax_steps: 50\nagent: x\nallowed_tools: [web.search]\n---\n"
        "contract_id: b\ngoal: g\nmax_steps: 50\nagent: y\nallowed_tools: [web.fetch]\n"
    )
    assert [c.contract_id for c in load_contracts(path)] == ["a", "b"]
