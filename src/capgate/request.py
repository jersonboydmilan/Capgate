"""The one primitive: ActionRequest.

Every tool call, inter-agent message and delegation is expressed as an
ActionRequest before it reaches the policy engine. There is deliberately no
field for "who asked for this" or "on whose behalf": authorization is always
computed from the acting agent alone.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

ACTION_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")

MESSAGE_ACTION = "agent.message"
DELEGATE_ACTION = "agent.delegate"


class MalformedRequest(ValueError):
    """Raised when a request cannot be represented canonically."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise MalformedRequest(f"arguments must be JSON-serializable: {exc}") from exc


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ActionRequest:
    """A structured proposal from an agent. Immutable once constructed.

    Arguments are frozen into canonical JSON at construction time, so the
    arguments that were authorized are exactly the arguments that execute —
    mutating the caller's dict afterwards has no effect.
    """

    agent_id: str
    action: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    contract_id: str | None = None

    def __post_init__(self) -> None:
        args = {} if self.arguments is None else self.arguments
        if not isinstance(args, Mapping):
            raise MalformedRequest("arguments must be a mapping")
        frozen = canonical_json(dict(args))
        object.__setattr__(self, "_arguments_json", frozen)
        object.__setattr__(self, "arguments", _ReadOnlyArgs(frozen))

    @property
    def arguments_json(self) -> str:
        return self._arguments_json  # type: ignore[attr-defined]

    @property
    def arguments_hash(self) -> str:
        return sha256_hex(self.arguments_json)

    def arguments_copy(self) -> dict[str, Any]:
        return json.loads(self.arguments_json)

    def problems(self) -> list[str]:
        issues = []
        if not isinstance(self.agent_id, str) or not self.agent_id:
            issues.append("agent_id must be a non-empty string")
        if not isinstance(self.action, str) or not ACTION_NAME.match(self.action):
            issues.append(f"invalid action name: {self.action!r}")
        if self.contract_id is not None and not isinstance(self.contract_id, str):
            issues.append("contract_id must be a string")
        return issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "contract_id": self.contract_id,
            "action": self.action,
            "arguments": self.arguments_copy(),
        }


class _ReadOnlyArgs(Mapping[str, Any]):
    """Mapping view that always hands out copies of nested values."""

    __slots__ = ("_json",)

    def __init__(self, frozen_json: str) -> None:
        self._json = frozen_json

    def _data(self) -> dict[str, Any]:
        return json.loads(self._json)

    def __getitem__(self, key: str) -> Any:
        return self._data()[key]

    def __iter__(self):
        return iter(self._data())

    def __len__(self) -> int:
        return len(self._data())

    def __repr__(self) -> str:
        return repr(self._data())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return self._data() == dict(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._json)


@dataclass(frozen=True)
class MessageRequest:
    """An inter-agent message. Converted to an ActionRequest; no parallel path."""

    sender: str
    recipient: str
    body: Any
    contract_id: str | None = None

    def to_action_request(self) -> ActionRequest:
        return ActionRequest(
            agent_id=self.sender,
            action=MESSAGE_ACTION,
            arguments={"to": self.recipient, "body": self.body},
            contract_id=self.contract_id,
        )


@dataclass(frozen=True)
class DelegationRequest:
    """Agent `sender` asks agent `recipient` to perform `action`.

    Produces two independent ActionRequests: the sender's request to delegate
    (checked under the sender's contract) and the recipient's action (checked
    under the recipient's contract only).
    """

    sender: str
    recipient: str
    action: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    contract_id: str | None = None

    def delegation_request(self) -> ActionRequest:
        return ActionRequest(
            agent_id=self.sender,
            action=DELEGATE_ACTION,
            arguments={"to": self.recipient, "action": self.action, "arguments": dict(self.arguments or {})},
            contract_id=self.contract_id,
        )

    def delegated_action(self) -> ActionRequest:
        # contract_id is intentionally None: the recipient acts under its own binding.
        return ActionRequest(agent_id=self.recipient, action=self.action, arguments=dict(self.arguments or {}))
