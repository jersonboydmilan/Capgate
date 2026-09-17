"""Capability grants and argument constraints.

A capability is an explicit grant for one exact action name. There are no
wildcards and no inheritance: an action that is not named is not permitted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit

from .decision import ReasonCode
from .netaddr import InvalidHost, ip_literal, is_private_host, normalize_hostname
from .request import ACTION_NAME, DELEGATE_ACTION, MESSAGE_ACTION, ActionRequest
from .timeutil import parse_timestamp

RESERVED_PREFIXES = ("harness.", "contract.")


class CapabilityError(ValueError):
    pass


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


CONSTRAINTS: dict[str, str] = {
    "allowed_arguments": "list of argument names; any other argument is rejected",
    "required_arguments": "list of argument names that must be present",
    "max_argument_length": "maximum length of any string value, at any depth",
    "url_argument": "name of the argument holding a URL (default: url)",
    "allowed_domains": "URL host must equal or be a subdomain of one of these",
    "blocked_domains": "URL host must not equal or be a subdomain of any of these",
    "block_private_hosts": "reject loopback, private, link-local and internal hostnames",
    "allowed_targets": "agent ids this agent may message or delegate to (required for agent.message / agent.delegate)",
    "allowed_actions": "actions this agent may ask another agent to perform (required for agent.delegate)",
    "max_calls": "maximum number of allowed invocations of this action per agent",
}

_LIST_CONSTRAINTS = {"allowed_arguments", "required_arguments", "allowed_domains", "blocked_domains", "allowed_targets", "allowed_actions"}
_INT_CONSTRAINTS = {"max_argument_length", "max_calls"}


@dataclass(frozen=True)
class Capability:
    action: str
    effect: Effect
    constraints: Mapping[str, Any] = field(default_factory=dict)
    expires_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"effect": self.effect.value}
        if self.constraints:
            data["constraints"] = {k: (list(v) if isinstance(v, tuple) else v) for k, v in self.constraints.items()}
        if self.expires_at is not None:
            data["expires_at"] = self.expires_at.isoformat()
        return data


def parse_capability(action: str, spec: Any) -> Capability:
    if not isinstance(action, str) or not ACTION_NAME.match(action):
        raise CapabilityError(f"invalid action name: {action!r}")
    if action.startswith(RESERVED_PREFIXES):
        raise CapabilityError(f"{action!r} is reserved: contracts cannot grant authority over the harness or contracts")

    if isinstance(spec, Capability):
        return spec
    if isinstance(spec, bool):
        raise CapabilityError(f"{action}: use 'allow', 'deny' or 'escalate', not a boolean")
    if isinstance(spec, str):
        spec = {"effect": spec}
    if not isinstance(spec, Mapping):
        raise CapabilityError(f"{action}: capability must be an effect string or a mapping")

    unknown = set(spec) - {"effect", "constraints", "expires_at"}
    if unknown:
        raise CapabilityError(f"{action}: unknown capability fields {sorted(unknown)}")
    try:
        effect = Effect(spec.get("effect"))
    except ValueError:
        raise CapabilityError(f"{action}: effect must be one of allow, deny, escalate") from None

    raw_constraints = spec.get("constraints") or {}
    if not isinstance(raw_constraints, Mapping):
        raise CapabilityError(f"{action}: constraints must be a mapping")
    constraints = _parse_constraints(action, raw_constraints)

    if effect is not Effect.DENY and action in (MESSAGE_ACTION, DELEGATE_ACTION) and "allowed_targets" not in constraints:
        raise CapabilityError(f"{action}: requires an explicit allowed_targets constraint")
    if effect is not Effect.DENY and action == DELEGATE_ACTION and "allowed_actions" not in constraints:
        raise CapabilityError(f"{action}: requires an explicit allowed_actions constraint")

    expires_at = None
    if spec.get("expires_at") is not None:
        try:
            expires_at = parse_timestamp(spec["expires_at"])
        except ValueError as exc:
            raise CapabilityError(f"{action}: {exc}") from None

    return Capability(action, effect, MappingProxyType(constraints), expires_at)


def _parse_constraints(action: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    unknown = set(raw) - set(CONSTRAINTS)
    if unknown:
        raise CapabilityError(f"{action}: unknown constraints {sorted(unknown)}")
    out: dict[str, Any] = {}
    for name, value in raw.items():
        if name in _LIST_CONSTRAINTS:
            if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and v for v in value):
                raise CapabilityError(f"{action}.{name}: must be a list of non-empty strings")
            items = tuple(v.lower().rstrip(".") for v in value) if name.endswith("domains") else tuple(value)
            out[name] = items
        elif name in _INT_CONSTRAINTS:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CapabilityError(f"{action}.{name}: must be a non-negative integer")
            out[name] = value
        elif name == "block_private_hosts":
            if not isinstance(value, bool):
                raise CapabilityError(f"{action}.{name}: must be true or false")
            out[name] = value
        elif name == "url_argument":
            if not isinstance(value, str) or not value:
                raise CapabilityError(f"{action}.{name}: must be a non-empty string")
            out[name] = value
    return out


@dataclass(frozen=True)
class ConstraintViolation:
    reason_code: ReasonCode
    rule: str
    detail: str


def check_constraints(capability: Capability, request: ActionRequest, calls_so_far: int) -> ConstraintViolation | None:
    """Return the first violated constraint, or None if all hold."""
    c = capability.constraints
    args = request.arguments_copy()

    if "max_calls" in c and calls_so_far >= c["max_calls"]:
        return ConstraintViolation(ReasonCode.BUDGET_EXHAUSTED, "constraint:max_calls", f"{request.action} limited to {c['max_calls']} calls")

    if "allowed_arguments" in c:
        extra = sorted(set(args) - set(c["allowed_arguments"]))
        if extra:
            return ConstraintViolation(ReasonCode.ARGUMENT_NOT_ALLOWED, "constraint:allowed_arguments", f"arguments not permitted: {extra}")

    if "required_arguments" in c:
        missing = sorted(set(c["required_arguments"]) - set(args))
        if missing:
            return ConstraintViolation(ReasonCode.ARGUMENT_MISSING, "constraint:required_arguments", f"missing arguments: {missing}")

    if "max_argument_length" in c:
        longest = _longest_string(args)
        if longest > c["max_argument_length"]:
            return ConstraintViolation(ReasonCode.ARGUMENT_NOT_ALLOWED, "constraint:max_argument_length", f"string argument of length {longest} exceeds {c['max_argument_length']}")

    if any(k in c for k in ("allowed_domains", "blocked_domains", "block_private_hosts")):
        violation = _check_url(c, args)
        if violation:
            return violation

    if "allowed_targets" in c:
        target = args.get("to")
        if not isinstance(target, str) or target not in c["allowed_targets"]:
            return ConstraintViolation(ReasonCode.TARGET_NOT_ALLOWED, "constraint:allowed_targets", f"target {target!r} not in allowed_targets")

    if "allowed_actions" in c:
        delegated = args.get("action")
        if not isinstance(delegated, str) or delegated not in c["allowed_actions"]:
            return ConstraintViolation(ReasonCode.DELEGATED_ACTION_NOT_ALLOWED, "constraint:allowed_actions", f"may not ask another agent to perform {delegated!r}")

    return None


def _longest_string(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, Mapping):
        return max([_longest_string(k) for k in value] + [_longest_string(v) for v in value.values()] + [0])
    if isinstance(value, list):
        return max([_longest_string(v) for v in value] + [0])
    return 0


_URL_FORBIDDEN_CHARS = re.compile(r"[\\\s\x00-\x1f\x7f]")


def _check_url(c: Mapping[str, Any], args: Mapping[str, Any]) -> ConstraintViolation | None:
    name = c.get("url_argument", "url")
    url = args.get(name)
    rule = "constraint:url"
    deny = lambda detail, r=rule: ConstraintViolation(ReasonCode.DOMAIN_NOT_ALLOWED, r, detail)
    if not isinstance(url, str):
        return deny(f"argument {name!r} must be a URL string")
    if _URL_FORBIDDEN_CHARS.search(url):
        # Backslashes, whitespace and control characters are parsed differently by different HTTP clients.
        return deny("URL contains backslashes, whitespace or control characters")
    try:
        parts = urlsplit(url)
        raw_host = parts.hostname or ""
        parts.port  # raises on a malformed port
    except ValueError:
        return deny("unparseable URL")
    if parts.scheme not in ("http", "https") or not raw_host:
        return deny("URL must be http(s) with a host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return deny("URLs with embedded credentials are not allowed")
    try:
        host = normalize_hostname(raw_host)
    except InvalidHost as exc:
        return deny(str(exc))

    def matches(domains: tuple[str, ...]) -> bool:
        return ip_literal(host) is None and any(host == d or host.endswith("." + d) for d in domains)

    if matches(c.get("blocked_domains", ())):
        return deny(f"host {host!r} is blocked", "constraint:blocked_domains")
    if c.get("block_private_hosts") and is_private_host(host):
        return deny(f"host {host!r} is private or internal", "constraint:block_private_hosts")
    if "allowed_domains" in c and not matches(c["allowed_domains"]):
        return deny(f"host {host!r} not in allowed_domains", "constraint:allowed_domains")
    return None
