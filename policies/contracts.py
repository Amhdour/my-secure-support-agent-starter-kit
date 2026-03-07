"""Policy contracts and runtime decision model."""

from dataclasses import dataclass, field
from typing import Mapping, Protocol


@dataclass(frozen=True)
class PolicyDecision:
    """Decision emitted by policy engine with optional runtime constraints."""

    request_id: str
    allow: bool
    reason: str
    risk_tier: str = "unknown"
    fallback_to_rag: bool = False
    constraints: Mapping[str, object] = field(default_factory=dict)


class PolicyEngine(Protocol):
    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        """Evaluate if an action is permitted under active policy."""
        ...
