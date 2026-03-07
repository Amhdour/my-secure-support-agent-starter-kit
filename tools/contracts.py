"""Tool contracts for mediated, policy-ready tool routing."""

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence


ALLOWED_DECISION = "allow"
DENY_DECISION = "deny"
REQUIRE_CONFIRMATION_DECISION = "require_confirmation"


@dataclass(frozen=True)
class ToolDescriptor:
    """Central tool configuration entry used by the registry/router."""

    name: str
    description: str
    allowed: bool
    confirmation_required: bool = False
    forbidden_actions: Sequence[str] = field(default_factory=tuple)
    forbidden_fields: Sequence[str] = field(default_factory=tuple)
    rate_limit_per_minute: int | None = None


@dataclass(frozen=True)
class ToolInvocation:
    """One mediated tool call request that must pass through the router."""

    request_id: str
    actor_id: str
    tenant_id: str
    tool_name: str
    action: str
    arguments: Mapping[str, object]
    confirmed: bool = False


@dataclass(frozen=True)
class ToolDecision:
    """Explicit router decision for safe tool mediation."""

    status: str
    tool_name: str
    action: str
    reason: str
    sanitized_arguments: Mapping[str, object] = field(default_factory=dict)


class ToolRegistry(Protocol):
    def register(self, tool: ToolDescriptor) -> None:
        """Register or update one tool descriptor."""
        ...

    def get(self, tool_name: str) -> ToolDescriptor | None:
        """Get one tool descriptor by name."""
        ...

    def list_allowlisted(self) -> Sequence[ToolDescriptor]:
        """List tools currently allowlisted for routing."""
        ...


class ToolRouter(Protocol):
    def route(self, invocation: ToolInvocation) -> ToolDecision:
        """Return allow/deny/require_confirmation decision for a tool invocation."""
        ...
