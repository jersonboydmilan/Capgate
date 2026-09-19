"""Rate limiting for the HTTP boundary.

Three token buckets, checked in order:

  1. per client address — before any token verification, so garbage traffic
     cannot buy CPU or audit writes;
  2. per authenticated principal (agent or approver id) — so one agent cannot
     starve the harness for the others, whatever address it comes from;
  3. per client address, for *audit records of failed authentication* — the
     first few failures in a window are recorded individually, the rest are
     counted and summarised in the next record, so a flood cannot grow the
     audit trail without bound while evidence of the flood is kept.

By default the buckets are in memory and per process (idle keys evicted, so
rotating source addresses cannot exhaust memory). With `shared: true` and a
state store, the buckets live in the store instead, so the limits hold across
all harness replicas rather than per replica.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class RateLimitConfig:
    client_rate: float = 20.0        # requests per second per client address
    client_burst: int = 100
    principal_rate: float = 10.0     # requests per second per principal
    principal_burst: int = 60
    auth_failure_audit_per_minute: int = 20
    max_tracked_keys: int = 10_000
    enabled: bool = True
    shared: bool = False   # use the state store so limits are enforced across replicas

    @classmethod
    def from_mapping(cls, data: dict | None) -> "RateLimitConfig":
        if not data:
            return cls()
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"rate_limit: unknown fields {sorted(unknown)}")
        return cls(**data)


class TokenBucket:
    """Many buckets keyed by string, with LRU eviction of idle keys."""

    def __init__(self, rate: float, burst: int, *, max_keys: int, clock: Callable[[], float] = time.monotonic) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate, self.burst, self.max_keys, self.clock = rate, burst, max_keys, clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str) -> tuple[bool, float]:
        """Consume one token. Returns (allowed, seconds until a token is available)."""
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.pop(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1:
                tokens -= 1
                allowed, retry = True, 0.0
            else:
                allowed, retry = False, (1 - tokens) / self.rate
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            return allowed, retry


class AuditSampler:
    """Allow N audit records per key per minute; count the rest."""

    def __init__(self, per_minute: int, *, max_keys: int, clock: Callable[[], float] = time.monotonic) -> None:
        self._bucket = TokenBucket(per_minute / 60.0, max(per_minute, 1), max_keys=max_keys, clock=clock) if per_minute > 0 else None
        self._suppressed: OrderedDict[str, int] = OrderedDict()
        self._max_keys = max_keys
        self._lock = threading.Lock()

    def admit(self, key: str) -> tuple[bool, int]:
        """Returns (record this one?, number suppressed since the last recorded one)."""
        allowed = self._bucket.take(key)[0] if self._bucket else False
        with self._lock:
            if not allowed:
                self._suppressed[key] = self._suppressed.pop(key, 0) + 1
                while len(self._suppressed) > self._max_keys:
                    self._suppressed.popitem(last=False)
                return False, 0
            return True, self._suppressed.pop(key, 0)


class RateLimiter:
    def __init__(self, config: RateLimitConfig | None = None, *, clock: Callable[[], float] | None = None, store: Any = None) -> None:
        self.config = config or RateLimitConfig()
        c = self.config
        self._store = store if c.shared else None
        # shared limits must use a wall clock the replicas agree on (Postgres uses its own clock)
        self._clock = clock or (time.time if self._store is not None else time.monotonic)
        if self._store is None:
            self._clients = TokenBucket(c.client_rate, c.client_burst, max_keys=c.max_tracked_keys, clock=self._clock)
            self._principals = TokenBucket(c.principal_rate, c.principal_burst, max_keys=c.max_tracked_keys, clock=self._clock)
            self._auth_audit = AuditSampler(c.auth_failure_audit_per_minute, max_keys=c.max_tracked_keys, clock=self._clock)

    def client(self, address: str) -> tuple[bool, float]:
        if not self.config.enabled:
            return True, 0.0
        if self._store is not None:
            return self._store.rate_take("client", address, self.config.client_rate, self.config.client_burst, self._clock())
        return self._clients.take(address)

    def principal(self, principal: str) -> tuple[bool, float]:
        if not self.config.enabled:
            return True, 0.0
        if self._store is not None:
            return self._store.rate_take("principal", principal, self.config.principal_rate, self.config.principal_burst, self._clock())
        return self._principals.take(principal)

    def audit_auth_failure(self, address: str) -> tuple[bool, int]:
        if not self.config.enabled:
            return True, 0
        if self._store is not None:
            return self._store.rate_admit("authfail", address, self.config.auth_failure_audit_per_minute, self._clock())
        return self._auth_audit.admit(address)
