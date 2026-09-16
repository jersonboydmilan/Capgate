"""Shared test fixtures: contracts, a controllable clock, and spy tools."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from harness import AuditLog, Harness, TaskContract

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: Any) -> None:
        self.now += timedelta(**kwargs)


class SpyTool:
    """Records every invocation. `calls == []` proves the tool was never reached."""

    def __init__(self, output: Any = "ok") -> None:
        self.calls: list[dict] = []
        self.output = output

    def __call__(self, arguments: dict) -> Any:
        self.calls.append(arguments)
        return self.output


def research_contract(**overrides: Any) -> TaskContract:
    data = {
        "contract_id": "research-v1",
        "goal": "research X",
        "max_steps": 20,
        "approvers": ["alice"],
        "agents": {
            "researcher": {
                "capabilities": {
                    "web.search": "allow",
                    "web.fetch": {
                        "effect": "allow",
                        "constraints": {"allowed_arguments": ["url"], "block_private_hosts": True, "blocked_domains": ["internal.example"]},
                    },
                    "database.write": "deny",
                    "create_agent": "deny",
                    "email.send": "escalate",
                }
            }
        },
    }
    data.update(overrides)
    return TaskContract.from_dict(data)


def delegation_contracts(*, b_can_write: bool = False, a_may_request: tuple[str, ...] = ("database.write", "web.search")) -> list[TaskContract]:
    """The canonical delegation-boundary setup.

    Contract A: web.search ✓, web.fetch ✓, database.write ✗, create_agent ✗,
                and may ask agent-b to perform `a_may_request`.
    Contract B: web.search ✓ (+ database.write if b_can_write).
    """
    contract_a = TaskContract.from_dict({
        "contract_id": "contract-a",
        "goal": "coordinate research", "max_steps": 50,
        "agents": {
            "agent-a": {
                "capabilities": {
                    "web.search": "allow",
                    "web.fetch": "allow",
                    "database.write": "deny",
                    "create_agent": "deny",
                    "agent.message": {"effect": "allow", "constraints": {"allowed_targets": ["agent-b"]}},
                    "agent.delegate": {"effect": "allow", "constraints": {"allowed_targets": ["agent-b"], "allowed_actions": list(a_may_request)}},
                }
            }
        },
    })
    b_caps: dict[str, Any] = {"web.search": "allow"}
    if b_can_write:
        b_caps["database.write"] = "allow"
    contract_b = TaskContract.from_dict({
        "contract_id": "contract-b",
        "goal": "answer research questions", "max_steps": 50,
        "approvers": ["alice"],
        "agents": {"agent-b": {"capabilities": b_caps}},
    })
    return [contract_a, contract_b]


def make_harness(contracts=None, *, tools=None, clock=None, **kwargs) -> Harness:
    return Harness(
        contracts if contracts is not None else research_contract(),
        tools=tools,
        audit=kwargs.pop("audit", AuditLog()),
        clock=clock or FakeClock(),
        **kwargs,
    )
