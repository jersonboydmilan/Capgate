from harness import ReasonCode, TaskContract
from helpers import delegation_contracts, make_harness


def test_max_steps_counts_every_proposal_including_denied():
    c = TaskContract.from_dict({"contract_id": "c", "goal": "g", "max_steps": 3, "agents": {"w": {"capabilities": {"web.search": "allow"}}}})
    harness = make_harness(c)
    assert harness.authorize("w", "shell.exec").denied  # probing still spends budget
    assert harness.authorize("w", "web.search").allowed
    assert harness.authorize("w", "web.search").allowed
    result = harness.authorize("w", "web.search")
    assert result.denied and result.reason_code is ReasonCode.BUDGET_EXHAUSTED


def test_max_calls_per_capability():
    c = TaskContract.from_dict({"contract_id": "c", "goal": "g", "max_steps": 50, "agents": {"w": {"capabilities": {
        "email.send": {"effect": "allow", "constraints": {"max_calls": 2}},
        "web.search": "allow",
    }}}})
    harness = make_harness(c)
    assert harness.authorize("w", "email.send").allowed
    assert harness.authorize("w", "email.send").allowed
    assert harness.authorize("w", "email.send").reason_code is ReasonCode.BUDGET_EXHAUSTED
    assert harness.authorize("w", "web.search").allowed


def test_budget_is_shared_by_all_agents_under_one_contract():
    c = TaskContract.from_dict({"contract_id": "c", "goal": "g", "max_steps": 2, "agents": {
        "w1": {"capabilities": {"web.search": "allow"}},
        "w2": {"capabilities": {"web.search": "allow"}},
    }})
    harness = make_harness(c)
    assert harness.authorize("w1", "web.search").allowed
    assert harness.authorize("w2", "web.search").allowed
    assert harness.authorize("w1", "web.search").reason_code is ReasonCode.BUDGET_EXHAUSTED


def test_flooding_messages_exhausts_sender_budget():
    contracts = delegation_contracts()
    a = contracts[0].to_dict()
    a["max_steps"] = 5
    from harness import TaskContract as TC
    harness = make_harness([TC.from_dict(a), contracts[1]])
    results = [harness.send_message("agent-a", "agent-b", f"spam {i}") for i in range(8)]
    assert sum(r.allowed for r in results) == 5
    assert results[-1].reason_code is ReasonCode.BUDGET_EXHAUSTED
    assert len(harness.receive("agent-b")) == 5
