"""TaskContract: the source of truth for a run.

Contracts are validated strictly (unknown fields are errors, so a typo can
never silently widen or drop a rule), frozen after construction, and
identified by a content hash that is written into every audit record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

import yaml

from .capability import Capability, CapabilityError, parse_capability
from .request import canonical_json, sha256_hex
from .timeutil import parse_timestamp

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TOP_LEVEL = {"contract_id", "goal", "version", "max_steps", "expires_at", "approvers", "agents", "agent", "allowed_tools"}


class ContractError(ValueError):
    pass


@dataclass(frozen=True)
class AgentGrant:
    agent_id: str
    capabilities: Mapping[str, Capability]


@dataclass(frozen=True)
class TaskContract:
    contract_id: str
    goal: str
    agents: Mapping[str, AgentGrant] = field(default_factory=dict)
    max_steps: int | None = None  # required; None is rejected at construction
    expires_at: datetime | None = None
    approvers: tuple[str, ...] = ()
    version: str = "1"

    def __post_init__(self) -> None:
        if not isinstance(self.contract_id, str) or not _ID.match(self.contract_id):
            raise ContractError(f"invalid contract_id: {self.contract_id!r}")
        if not isinstance(self.goal, str) or not self.goal.strip():
            raise ContractError(f"{self.contract_id}: goal must be a non-empty string")
        if self.max_steps is None:
            raise ContractError(
                f"{self.contract_id}: max_steps is required — every contract needs a step budget "
                "(it bounds probing, escalation spam and message floods)"
            )
        if isinstance(self.max_steps, bool) or not isinstance(self.max_steps, int) or self.max_steps < 1:
            raise ContractError(f"{self.contract_id}: max_steps must be a positive integer")
        if self.expires_at is not None:
            try:
                object.__setattr__(self, "expires_at", parse_timestamp(self.expires_at))
            except ValueError as exc:
                raise ContractError(f"{self.contract_id}: {exc}") from None

        if not isinstance(self.agents, Mapping) or not self.agents:
            raise ContractError(f"{self.contract_id}: at least one agent must be declared")
        agents: dict[str, AgentGrant] = {}
        for agent_id, grant in self.agents.items():
            if not isinstance(agent_id, str) or not _ID.match(agent_id):
                raise ContractError(f"{self.contract_id}: invalid agent id {agent_id!r}")
            agents[agent_id] = _parse_agent(self.contract_id, agent_id, grant)
        object.__setattr__(self, "agents", MappingProxyType(agents))

        approvers = tuple(self.approvers or ())
        for approver in approvers:
            if not isinstance(approver, str) or not _ID.match(approver):
                raise ContractError(f"{self.contract_id}: invalid approver id {approver!r}")
            if approver in agents:
                raise ContractError(f"{self.contract_id}: {approver!r} cannot be both an agent and an approver")
        object.__setattr__(self, "approvers", approvers)
        object.__setattr__(self, "version", str(self.version))
        object.__setattr__(self, "_hash", "sha256:" + sha256_hex(canonical_json(self.to_dict())))

    @property
    def content_hash(self) -> str:
        return self._hash  # type: ignore[attr-defined]

    def capabilities_for(self, agent_id: str) -> Mapping[str, Capability]:
        grant = self.agents.get(agent_id)
        return grant.capabilities if grant else MappingProxyType({})

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "version": self.version,
            "goal": self.goal,
            "max_steps": self.max_steps,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "approvers": list(self.approvers),
            "agents": {
                agent_id: {"capabilities": {a: c.to_dict() for a, c in sorted(g.capabilities.items())}}
                for agent_id, g in sorted(self.agents.items())
            },
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskContract":
        if not isinstance(data, Mapping):
            raise ContractError("contract must be a mapping")
        unknown = set(data) - _TOP_LEVEL
        if unknown:
            raise ContractError(f"unknown contract fields: {sorted(unknown)}")
        for required in ("contract_id", "goal"):
            if required not in data:
                raise ContractError(f"missing required field: {required}")

        agents = data.get("agents")
        if "allowed_tools" in data or "agent" in data:
            # Shorthand: a single agent whose allowed_tools are plain grants.
            if agents is not None:
                raise ContractError("use either 'agents' or the 'agent' + 'allowed_tools' shorthand, not both")
            agent_id, tools = data.get("agent"), data.get("allowed_tools")
            if agent_id is None or tools is None:
                raise ContractError("the shorthand form requires both 'agent' and 'allowed_tools'")
            if not isinstance(tools, list):
                raise ContractError("allowed_tools must be a list")
            agents = {agent_id: {"capabilities": {t: "allow" for t in tools}}}

        return cls(
            contract_id=data["contract_id"],
            goal=data["goal"],
            agents=agents or {},
            max_steps=data.get("max_steps"),
            expires_at=data.get("expires_at"),
            approvers=tuple(data.get("approvers") or ()),
            version=data.get("version", "1"),
        )


def _parse_agent(contract_id: str, agent_id: str, grant: Any) -> AgentGrant:
    if isinstance(grant, AgentGrant):
        return grant
    if not isinstance(grant, Mapping):
        raise ContractError(f"{contract_id}.{agent_id}: agent entry must be a mapping")
    unknown = set(grant) - {"capabilities"}
    if unknown:
        raise ContractError(f"{contract_id}.{agent_id}: unknown fields {sorted(unknown)}")
    raw = grant.get("capabilities") or {}
    if not isinstance(raw, Mapping):
        raise ContractError(f"{contract_id}.{agent_id}: capabilities must be a mapping of action -> effect")
    caps: dict[str, Capability] = {}
    for action, spec in raw.items():
        try:
            caps[action] = parse_capability(action, spec)
        except CapabilityError as exc:
            raise ContractError(f"{contract_id}.{agent_id}: {exc}") from None
    return AgentGrant(agent_id, MappingProxyType(caps))


def load_contracts(path: str | Path) -> list[TaskContract]:
    """Load one or more contracts from a YAML file (multi-document supported)."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ContractError(f"{path}: invalid YAML: {exc}") from None
    if not docs:
        raise ContractError(f"{path}: no contracts found")
    contracts: list[TaskContract] = []
    for doc in docs:
        if isinstance(doc, Mapping) and set(doc) == {"contracts"}:
            contracts.extend(TaskContract.from_dict(d) for d in doc["contracts"])
        else:
            contracts.append(TaskContract.from_dict(doc))
    return contracts


def load_contract(path: str | Path) -> TaskContract:
    contracts = load_contracts(path)
    if len(contracts) != 1:
        raise ContractError(f"{path}: expected exactly one contract, found {len(contracts)}")
    return contracts[0]


def build_bindings(contracts: Iterable[TaskContract]) -> tuple[dict[str, TaskContract], dict[str, str]]:
    """Index contracts by id and bind each agent to exactly one contract."""
    by_id: dict[str, TaskContract] = {}
    bindings: dict[str, str] = {}
    all_approvers: set[str] = set()
    for contract in contracts:
        if contract.contract_id in by_id:
            raise ContractError(f"duplicate contract_id: {contract.contract_id}")
        by_id[contract.contract_id] = contract
        all_approvers.update(contract.approvers)
        for agent_id in contract.agents:
            if agent_id in bindings:
                raise ContractError(f"agent {agent_id!r} is bound to both {bindings[agent_id]!r} and {contract.contract_id!r}; an agent acts under exactly one contract")
            bindings[agent_id] = contract.contract_id
    overlap = all_approvers & set(bindings)
    if overlap:
        raise ContractError(f"approvers cannot also be agents: {sorted(overlap)}")
    return by_id, bindings
