from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Callable

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp. Naive values are rejected: expiry must be unambiguous."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        raise ValueError("expires_at must be a full timestamp with timezone, not a date")
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"invalid timestamp: {value!r}") from None
    else:
        raise ValueError(f"invalid timestamp: {value!r}")
    if dt.tzinfo is None:
        raise ValueError(f"timestamp must include a timezone: {value!r}")
    return dt.astimezone(timezone.utc)
