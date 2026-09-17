"""The five production-grade pieces, working together in one flow:
contract (YAML) → proposal → deterministic decision → enforced execution → audit.
"""

import pytest

from capgate import AuditLog, ExecutionRefused, Harness, load_contract, load_audit
from helpers import SpyTool

CONTRACT = """
contract_id: research-v1
goal: research X
max_steps: 20
agents:
  researcher:
    capabilities:
      web.search: allow
      database.write: deny
"""


def test_five_pieces_end_to_end(tmp_path):
    (tmp_path / "contract.yaml").write_text(CONTRACT)
    contract = load_contract(tmp_path / "contract.yaml")                      # 1. contract
    search, db = SpyTool({"results": ["a"]}), SpyTool()
    audit_path = tmp_path / "audit.jsonl"
    harness = Harness(contract, tools={"web.search": search, "database.write": db}, audit=AuditLog(audit_path))

    ok = harness.authorize(agent="researcher", action="web.search", arguments={"query": "x"})   # 2. proposal
    bad = harness.authorize(agent="researcher", action="database.write", arguments={"row": 1})

    assert (ok.decision.decision.value, ok.reason_code.value) == ("allow", "CAPABILITY_GRANTED")  # 3. decision
    assert (bad.decision.decision.value, bad.reason_code.value) == ("deny", "EXPLICITLY_DENIED")

    assert harness.execute(ok).output == {"results": ["a"]}                   # 4. enforcement
    with pytest.raises(ExecutionRefused):
        harness.execute(bad)
    assert search.calls == [{"query": "x"}] and db.calls == []

    records = load_audit(audit_path)                                           # 5. audit (verified chain, from disk)
    by_decision = {}
    for r in records:
        by_decision.setdefault(r.get("decision_id"), []).append(r["event"])
    assert by_decision[ok.decision_id] == ["decision", "execution"]
    assert by_decision[bad.decision_id] == ["decision", "execution_refused"]
