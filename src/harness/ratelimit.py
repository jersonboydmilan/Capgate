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

State is in memory and per process. The number of tracked keys is capped;
idle keys are evicted first, so rotating source addresses cannot exhaust memory.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class RateLimitConfig:
    client_rate: float = 20.0        # requests per second per client address
    client_burst: int = 100
    principal_rate: float = 10.0     # requests per second per principal
    principal_burst: int = 60
    auth_failure_audit_per_minute: int = 20
    max_tracked_keys: int = 10_000
    enabled: bool = True

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
    def __init__(self, config: RateLimitConfig | None = None, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.config = config or RateLimitConfig()
        c = self.config
        self._clients = TokenBucket(c.client_rate, c.client_burst, max_keys=c.max_tracked_keys, clock=clock)
        self._principals = TokenBucket(c.principal_rate, c.principal_burst, max_keys=c.max_tracked_keys, clock=clock)
        self._auth_audit = AuditSampler(c.auth_failure_audit_per_minute, max_keys=c.max_tracked_keys, clock=clock)

    def client(self, address: str) -> tuple[bool, float]:
        return self._clients.take(address) if self.config.enabled else (True, 0.0)

    def principal(self, principal: str) -> tuple[bool, float]:
        return self._principals.take(principal) if self.config.enabled else (True, 0.0)

    def audit_auth_failure(self, address: str) -> tuple[bool, int]:
        return self._auth_audit.admit(address) if self.config.enabled else (True, 0)
