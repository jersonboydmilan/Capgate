"""Fuzz the pure policy engine and the contract loader."""

from datetime import datetime, timezone

from hypothesis import given, strategies as st

from capgate import ActionRequest, ContractError, DecisionType, TaskContract, evaluate
from capgate.capability import Effect
from capgate.contract import build_bindings
from capgate.policy import Usage
from capgate.request import MalformedRequest

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
names = st.one_of(st.sampled_from(["web.search", "web.fetch", "agent.delegate", "agent.message", "db.write", "harness.x", "contract.y"]), st.text(max_size=20))
leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20), st.sampled_from(["allow", "deny", "escalate", "http://127.1/", "https://example.com"]))
value = st.recursive(leaf, lambda c: st.one_of(st.lists(c, max_size=3), st.dictionaries(st.text(max_size=12), c, max_size=3)), max_leaves=10)

CONTRACT = TaskContract.from_dict({"contract_id": "c", "goal": "g", "max_steps": 10, "agents": {
    "a": {"capabilities": {
        "web.search": "allow",
        "web.fetch": {"effect": "allow", "constraints": {"allowed_domains": ["example.com"], "block_private_hosts": True, "allowed_arguments": ["url"]}},
        "db.write": "deny",
        "agent.delegate": {"effect": "escalate", "constraints": {"allowed_targets": ["b"], "allowed_actions": ["web.search"]}},
    }},
    "b": {"capabilities": {"web.search": "allow"}},
}})
CONTRACTS, BINDINGS = build_bindings([CONTRACT])


@given(agent=st.one_of(st.sampled_from(["a", "b", "z"]), st.text(max_size=8)), action=names,
       arguments=st.dictionaries(st.text(max_size=10), value, max_size=4), contract_id=st.one_of(st.none(), st.sampled_from(["c", "x"]), st.text(max_size=5)),
       steps=st.integers(0, 20))
def test_evaluate_is_total_and_deny_by_default(agent, action, arguments, contract_id, steps):
    try:
        request = ActionRequest(agent, action, arguments, contract_id)
    except MalformedRequest:
        return
    result = evaluate(request, CONTRACTS, BINDINGS, Usage(contract_steps=steps), NOW)
    if result.decision is not DecisionType.DENY:
        cap = CONTRACT.capabilities_for(agent).get(action)
        assert cap is not None and cap.effect in (Effect.ALLOW, Effect.ESCALATE)
        assert steps < CONTRACT.max_steps
        assert contract_id in (None, "c")
    assert evaluate(request, CONTRACTS, BINDINGS, Usage(contract_steps=steps), NOW) == result  # deterministic


@given(data=st.dictionaries(st.sampled_from(["contract_id", "goal", "max_steps", "agents", "agent", "allowed_tools", "approvers", "expires_at", "version", "extra"]), value, max_size=8))
def test_contract_loader_only_raises_contract_error(data):
    try:
        TaskContract.from_dict(data)
    except ContractError:
        pass
