"""Task files, simulation and enforcement runs.

`simulate` and `enforce` run the same steps through the same Harness and the
same policy engine; the only difference is the Mode. Simulation cannot drift
from enforcement because there is no second implementation to drift.
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

from .audit import AuditLog
from .contract import ContractError, TaskContract, load_contracts
from .core import AuthorizationResult, DelegationResult, Harness, Mode
from .executor import ExecutionRefused
from .tools import build_tools

_TASK_FIELDS = {"name", "contract", "contracts", "agent", "steps", "tools"}


class TaskError(ValueError):
    pass


@dataclass(frozen=True)
class Step:
    kind: str  # action | message | delegate
    agent: str
    action: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    to: str | None = None
    body: Any = None


@dataclass(frozen=True)
class TaskFile:
    path: Path
    name: str
    contracts: list[TaskContract]
    steps: list[Step]
    tools: Mapping[str, Any]


def load_task(path: str | Path) -> TaskFile:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise TaskError(f"{path}: invalid YAML: {exc}") from None
    return task_from_mapping(data, base_dir=path.parent, name=path.stem, label=str(path))


def contracts_from_text(text: str) -> list[TaskContract]:
    """Parse one or more contracts from YAML text (multi-document or a `contracts:` list)."""
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid YAML: {exc}") from None
    if not docs:
        raise ContractError("no contracts found")
    out: list[TaskContract] = []
    for doc in docs:
        if isinstance(doc, Mapping) and set(doc) == {"contracts"}:
            out.extend(TaskContract.from_dict(d) for d in doc["contracts"])
        else:
            out.append(TaskContract.from_dict(doc))
    return out


def task_from_text(task_text: str, *, contracts_text: str | None = None, base_dir: str | Path = ".", name: str = "task") -> TaskFile:
    """Build a task from YAML text. `contracts_text`, if given, replaces the task's contract references."""
    try:
        data = yaml.safe_load(task_text)
    except yaml.YAMLError as exc:
        raise TaskError(f"task: invalid YAML: {exc}") from None
    contracts = contracts_from_text(contracts_text) if contracts_text and contracts_text.strip() else None
    return task_from_mapping(data, base_dir=Path(base_dir), name=name, label="task", contracts=contracts)


def task_from_mapping(data: Any, *, base_dir: Path, name: str, label: str, contracts: list[TaskContract] | None = None) -> TaskFile:
    if not isinstance(data, Mapping):
        raise TaskError(f"{label}: task must be a mapping")
    unknown = set(data) - _TASK_FIELDS
    if unknown:
        raise TaskError(f"{label}: unknown task fields {sorted(unknown)}")

    if contracts is None:
        contracts = []
        sources = []
        if "contract" in data:
            sources.append(data["contract"])
        sources.extend(data.get("contracts") or [])
        if not sources:
            raise TaskError(f"{label}: a task needs 'contract' or 'contracts'")
        for source in sources:
            if isinstance(source, str):
                contracts.extend(load_contracts((base_dir / source).resolve()))
            elif isinstance(source, Mapping):
                contracts.append(TaskContract.from_dict(source))
            else:
                raise TaskError(f"{label}: contract entries must be a path or a mapping")

    default_agent = data.get("agent")
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise TaskError(f"{label}: 'steps' must be a non-empty list")
    steps = [_parse_step(Path(label), i + 1, raw, default_agent) for i, raw in enumerate(raw_steps)]
    return TaskFile(base_dir / f"{name}.yaml", str(data.get("name") or name), contracts, steps, data.get("tools") or {})


def _parse_step(path: Path, index: int, raw: Any, default_agent: str | None) -> Step:
    where = f"{path}: step {index}"
    if not isinstance(raw, Mapping):
        raise TaskError(f"{where}: must be a mapping")
    agent = raw.get("agent", default_agent)
    if not isinstance(agent, str):
        raise TaskError(f"{where}: no agent (set 'agent' on the step or at the top of the task)")
    if "action" in raw:
        unknown = set(raw) - {"action", "arguments", "agent"}
        if unknown:
            raise TaskError(f"{where}: unknown fields {sorted(unknown)}")
        return Step("action", agent, raw["action"], raw.get("arguments") or {})
    if "message" in raw:
        msg = raw["message"] or {}
        return Step("message", agent, "agent.message", to=msg.get("to"), body=msg.get("body"))
    if "delegate" in raw:
        d = raw["delegate"] or {}
        return Step("delegate", agent, d.get("action"), d.get("arguments") or {}, to=d.get("to"))
    raise TaskError(f"{where}: expected one of 'action', 'message' or 'delegate'")


@dataclass
class Row:
    index: str
    agent: str
    label: str
    decision: str
    reason: str
    outcome: str
    detail: str
    action: str = ""
    rule: str | None = None
    capability: str | None = None
    contract_id: str | None = None
    decision_id: str | None = None


@dataclass
class Report:
    task: TaskFile
    mode: Mode
    rows: list[Row]
    audit: AuditLog

    def counts(self) -> Counter:
        return Counter(r.decision for r in self.rows)


Approver = Callable[[AuthorizationResult], "tuple[bool, str] | None"]


def run_task(task: TaskFile, mode: Mode | str, *, audit: AuditLog | None = None, approve: Approver | None = None, approver_id: str | None = None) -> Report:
    mode = Mode(mode)
    tools = build_tools(task.tools) if mode is Mode.ENFORCE else {}
    harness = Harness(task.contracts, tools=tools, audit=audit, mode=mode)
    rows: list[Row] = []

    for i, step in enumerate(task.steps, start=1):
        idx = f"{i:02d}"
        if step.kind == "action":
            result = harness.authorize(step.agent, step.action, dict(step.arguments))
            result = _maybe_approve(harness, result, approve, approver_id)
            rows.append(_row(harness, idx, step.agent, step.action, result))
        elif step.kind == "message":
            result = harness.send_message(step.agent, step.to, step.body)
            outcome = "delivered" if result.allowed and mode is Mode.ENFORCE else None
            rows.append(_row(harness, idx, step.agent, f"agent.message → {step.to}", result, outcome=outcome, execute=False))
        else:
            delegation = harness.delegate(step.agent, step.to, step.action, dict(step.arguments))
            first = _maybe_approve(harness, delegation.delegation, approve, approver_id)
            if isinstance(first, DelegationResult):
                delegation = first
            rows.append(_row(harness, idx, step.agent, f"agent.delegate → {step.to} ({step.action})", delegation.delegation, execute=False))
            if delegation.action is not None:
                action = _maybe_approve(harness, delegation.action, approve, approver_id)
                rows.append(_row(harness, "  ↳", step.to, step.action, action))
    return Report(task, mode, rows, harness.audit)


def _maybe_approve(harness: Harness, result: AuthorizationResult, approve: Approver | None, approver_id: str | None):
    if not result.escalated or approve is None or approver_id is None or harness.mode is Mode.SIMULATE:
        return result
    verdict = approve(result)
    if verdict is None:
        return result
    ok, note = verdict
    if ok:
        return harness.approve(result.approval_id, approver_id, note)
    return harness.reject(result.approval_id, approver_id, note)


def _row(harness: Harness, idx: str, agent: str, label: str, result: AuthorizationResult, *, outcome: str | None = None, execute: bool = True) -> Row:
    if outcome is None:
        if harness.mode is Mode.SIMULATE:
            outcome = "not executed"
        elif result.escalated:
            outcome = "awaiting approval"
        elif not result.allowed:
            outcome = "blocked"
        elif execute:
            try:
                outcome = harness.execute(result).status
            except ExecutionRefused as refusal:
                outcome = f"refused ({refusal.reason})"
        else:
            outcome = "authorized"
    d = result.decision
    return Row(
        idx, agent, label, d.decision.value.upper(), result.reason_code.value, outcome, d.detail,
        action=d.request.action, rule=d.rule, capability=d.capability, contract_id=d.contract_id, decision_id=d.decision_id,
    )


# -- rendering -------------------------------------------------------------

_COLORS = {"ALLOW": "32", "DENY": "31", "ESCALATE": "33"}


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


def render(report: Report, *, stream=None, verbose: bool = False) -> str:
    color = _use_color(stream or sys.stdout)
    paint = (lambda text, code: f"\033[{code}m{text}\033[0m") if color else (lambda text, code: text)
    agents = sorted({r.agent for r in report.rows})
    multi = len(agents) > 1
    enforce = report.mode is Mode.ENFORCE

    title = "AGENT HARNESS — " + ("ENFORCEMENT" if enforce else "SIMULATION")
    lines = [paint(title, "1"), ""]
    lines.append("Contract: " + ", ".join(c.contract_id for c in report.task.contracts))
    lines.append(("Agents: " if multi else "Agent: ") + ", ".join(agents))
    lines.append("")

    label_w = max(30, *(len(r.label) + (len(r.agent) + 2 if multi else 0) for r in report.rows)) + 2
    header = f"{'':4}{'ACTION':<{label_w}}{'DECISION':<11}{'REASON':<30}"
    if enforce:
        header += "OUTCOME"
    lines.append(header.rstrip())
    lines.append("─" * len(header.rstrip()))
    for r in report.rows:
        label = f"{r.agent}: {r.label}" if multi else r.label
        decision = paint(f"{r.decision:<11}", _COLORS.get(r.decision, "0"))
        line = f"{r.index:<4}{label:<{label_w}}{decision}{r.reason:<30}"
        if enforce:
            line += r.outcome
        lines.append(line.rstrip())
        if verbose:
            lines.append(f"{'':4}  {r.detail}")

    counts = report.counts()
    lines += ["", "Summary", "─" * 16]
    lines.append(f"Allowed:      {counts.get('ALLOW', 0)}")
    lines.append(f"Denied:       {counts.get('DENY', 0)}")
    lines.append(f"Escalated:    {counts.get('ESCALATE', 0)}")
    lines.append("")
    if enforce:
        executed = sum(1 for r in report.rows if r.outcome in ("succeeded", "delivered"))
        lines.append(f"Executed {executed} action(s). {len(report.audit)} audit record(s) written.")
    else:
        lines.append("No external actions were executed.")
    return "\n".join(lines)
