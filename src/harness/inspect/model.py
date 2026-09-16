"""Pure functions behind `harness inspect`: simulate, explain, grants, diff, audit views.

Nothing here touches the network or mutates authority state, so every view is
safe to recompute on each keystroke.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..audit import GENESIS, _hash_record
from ..contract import ContractError, TaskContract, build_bindings
from ..core import Mode
from ..policy import Usage, evaluate
from ..request import ActionRequest, MalformedRequest
from ..simulation import TaskError, contracts_from_text, run_task, task_from_text
from ..timeutil import utc_now


class InputError(ValueError):
    """User-correctable input problem; shown inline in the UI."""


def _contracts(text: str) -> list[TaskContract]:
    try:
        contracts = contracts_from_text(text)
        build_bindings(contracts)
        return contracts
    except ContractError as exc:
        raise InputError(f"contract: {exc}") from None


# -- simulation ------------------------------------------------------------------

def simulate(task_text: str, contracts_text: str, base_dir: str | Path = ".") -> dict[str, Any]:
    try:
        task = task_from_text(task_text, contracts_text=contracts_text, base_dir=base_dir)
    except (TaskError, ContractError, FileNotFoundError) as exc:
        raise InputError(str(exc)) from None
    try:
        build_bindings(task.contracts)
    except ContractError as exc:
        raise InputError(f"contract: {exc}") from None
    report = run_task(task, Mode.SIMULATE)
    counts = report.counts()
    return {
        "task": task.name,
        "contracts": [{"contract_id": c.contract_id, "hash": c.content_hash, "agents": sorted(c.agents)} for c in task.contracts],
        "rows": [asdict(r) for r in report.rows],
        "summary": {"allow": counts.get("ALLOW", 0), "deny": counts.get("DENY", 0), "escalate": counts.get("ESCALATE", 0)},
        "grants": grants_from_contracts(task.contracts),
    }


# -- policy explorer ---------------------------------------------------------------

def grants_from_contracts(contracts: list[TaskContract]) -> list[dict[str, Any]]:
    out = []
    for contract in contracts:
        for agent_id, grant in sorted(contract.agents.items()):
            for action, cap in sorted(grant.capabilities.items()):
                out.append({
                    "contract_id": contract.contract_id,
                    "agent": agent_id,
                    "action": action,
                    "effect": cap.effect.value,
                    "constraints": cap.to_dict().get("constraints", {}),
                    "expires_at": cap.expires_at.isoformat() if cap.expires_at else None,
                })
    return out


def policy(contracts_text: str) -> dict[str, Any]:
    contracts = _contracts(contracts_text)
    return {
        "contracts": [
            {
                "contract_id": c.contract_id,
                "hash": c.content_hash,
                "goal": c.goal,
                "max_steps": c.max_steps,
                "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                "approvers": list(c.approvers),
                "agents": sorted(c.agents),
            }
            for c in contracts
        ],
        "grants": grants_from_contracts(contracts),
    }


def explain(contracts_text: str, agent: str, action: str, arguments: Any, contract_id: str | None = None) -> dict[str, Any]:
    """What would this proposal hit? Pure evaluation with empty budgets — nothing is consumed or recorded."""
    contracts = _contracts(contracts_text)
    by_id, bindings = build_bindings(contracts)
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError as exc:
            raise InputError(f"arguments: not valid JSON ({exc.msg})") from None
    try:
        request = ActionRequest(agent, action, arguments if arguments is not None else {}, contract_id or None)
    except MalformedRequest as exc:
        raise InputError(str(exc)) from None
    evaluation = evaluate(request, by_id, bindings, Usage(), utc_now())
    bound = bindings.get(agent)
    return {
        "decision": evaluation.decision.value,
        "reason_code": evaluation.reason_code.value,
        "detail": evaluation.detail,
        "rule": evaluation.rule,
        "capability": evaluation.capability,
        "bound_contract": bound,
        "note": "Evaluated with empty budgets at the current time; step and call limits are not reflected.",
    }


def diff(left_text: str, right_text: str) -> dict[str, Any]:
    left, right = _contracts(left_text), _contracts(right_text)
    lg = {(g["agent"], g["action"]): g for g in grants_from_contracts(left)}
    rg = {(g["agent"], g["action"]): g for g in grants_from_contracts(right)}
    changes = []
    for key in sorted(set(lg) | set(rg)):
        a, b = lg.get(key), rg.get(key)
        if a and not b:
            status = "removed"
        elif b and not a:
            status = "added"
        elif (a["effect"], a["constraints"], a["expires_at"]) != (b["effect"], b["constraints"], b["expires_at"]):
            status = "widened" if _rank(b["effect"]) > _rank(a["effect"]) else "narrowed" if _rank(b["effect"]) < _rank(a["effect"]) else "changed"
        else:
            continue
        changes.append({"agent": key[0], "action": key[1], "status": status, "before": a, "after": b})

    def meta(cs):
        return {c.contract_id: {"max_steps": c.max_steps, "expires_at": c.expires_at.isoformat() if c.expires_at else None, "approvers": sorted(c.approvers)} for c in cs}

    lm, rm = meta(left), meta(right)
    contract_changes = [
        {"contract_id": cid, "before": lm.get(cid), "after": rm.get(cid)}
        for cid in sorted(set(lm) | set(rm)) if lm.get(cid) != rm.get(cid)
    ]
    return {"grants": changes, "contracts": contract_changes}


def _rank(effect: str) -> int:
    return {"deny": 0, "escalate": 1, "allow": 2}[effect]


# -- audit browser ---------------------------------------------------------------------

def audit_view(path: str | Path, *, agent: str = "", action: str = "", decision: str = "", event: str = "", decision_id: str = "", limit: int = 500) -> dict[str, Any]:
    path = Path(path).expanduser()
    if not path.is_file():
        raise InputError(f"audit file not found: {path}")
    verification: dict[str, Any] = {"ok": True, "error": None, "bad_sequence": None}
    prev = GENESIS
    total = 0
    matched: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                if verification["ok"]:
                    verification.update(ok=False, error=f"line {index + 1}: not valid JSON", bad_sequence=total)
                total += 1
                continue
            if verification["ok"]:
                problem = None
                if record.get("sequence") != total:
                    problem = "sequence gap or reordering"
                elif record.get("prev_hash") != prev:
                    problem = "chain broken (prev_hash mismatch)"
                elif record.get("hash") != _hash_record(record):
                    problem = "contents modified"
                if problem:
                    verification.update(ok=False, error=f"record {total}: {problem}", bad_sequence=total)
                prev = record.get("hash")
            record["_valid"] = verification["ok"]
            total += 1
            if agent and record.get("agent_id") != agent:
                continue
            if action and record.get("action") != action:
                continue
            if decision and record.get("decision") != decision:
                continue
            if event and record.get("event") != event:
                continue
            if decision_id and decision_id not in (record.get("decision_id"), record.get("resulting_decision_id")):
                continue
            matched.append(record)
    return {
        "path": str(path),
        "total": total,
        "verification": verification,
        "records": matched[-limit:],
        "truncated": len(matched) > limit,
        "matched": len(matched),
    }
