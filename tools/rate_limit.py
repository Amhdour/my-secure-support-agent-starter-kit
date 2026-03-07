"""Per-tool in-memory rate limiting primitives."""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol


class ToolRateLimiter(Protocol):
    def allow(self, key: str, limit_per_minute: int) -> bool:
        """Return True when key is within configured per-minute limit."""
        ...


@dataclass
class InMemoryToolRateLimiter(ToolRateLimiter):
    """Sliding-window per-minute limiter for tool usage."""

    _events: dict[str, deque[datetime]] = field(default_factory=dict)

    def allow(self, key: str, limit_per_minute: int) -> bool:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=1)
        events = self._events.setdefault(key, deque())

        while events and events[0] < window_start:
            events.popleft()

        if len(events) >= limit_per_minute:
            return False

        events.append(now)
        return True
