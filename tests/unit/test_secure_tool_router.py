"""Tests for secure tool routing decisions and enforcement."""

from tools.contracts import (
    ALLOWED_DECISION,
    DENY_DECISION,
    REQUIRE_CONFIRMATION_DECISION,
    ToolDescriptor,
    ToolInvocation,
)
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


def _router_with_tool(tool: ToolDescriptor) -> SecureToolRouter:
    registry = InMemoryToolRegistry()
    registry.register(tool)
    return SecureToolRouter(registry=registry, rate_limiter=InMemoryToolRateLimiter())


def _invocation(*, tool_name: str, arguments: dict[str, object] | None = None, confirmed: bool = False):
    return ToolInvocation(
        request_id="req-1",
        actor_id="user-1",
        tenant_id="tenant-a",
        tool_name=tool_name,
        action="lookup",
        arguments=arguments or {"ticket_id": "T-1"},
        confirmed=confirmed,
    )


def test_allowlisted_tool_execution() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True)
    )

    decision, result = router.mediate_and_execute(
        _invocation(tool_name="ticket_lookup"),
        executor=lambda _: {"ok": True},
    )

    assert decision.status == ALLOWED_DECISION
    assert result == {"ok": True}


def test_forbidden_tool_denial() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=False)
    )

    decision = router.route(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert "allowlisted" in decision.reason


def test_forbidden_field_blocking() -> None:
    router = _router_with_tool(
        ToolDescriptor(
            name="ticket_lookup",
            description="lookup",
            allowed=True,
            forbidden_fields=("ssn",),
        )
    )

    decision = router.route(_invocation(tool_name="ticket_lookup", arguments={"ticket_id": "T-1", "ssn": "1"}))

    assert decision.status == DENY_DECISION
    assert "forbidden argument fields" in decision.reason


def test_confirmation_required_flow() -> None:
    router = _router_with_tool(
        ToolDescriptor(
            name="account_update",
            description="update",
            allowed=True,
            confirmation_required=True,
        )
    )

    unconfirmed = router.route(_invocation(tool_name="account_update", confirmed=False))
    confirmed = router.route(_invocation(tool_name="account_update", confirmed=True))

    assert unconfirmed.status == REQUIRE_CONFIRMATION_DECISION
    assert confirmed.status == ALLOWED_DECISION


def test_rate_limit_enforcement() -> None:
    router = _router_with_tool(
        ToolDescriptor(
            name="ticket_lookup",
            description="lookup",
            allowed=True,
            rate_limit_per_minute=1,
        )
    )

    first = router.route(_invocation(tool_name="ticket_lookup"))
    second = router.route(_invocation(tool_name="ticket_lookup"))

    assert first.status == ALLOWED_DECISION
    assert second.status == DENY_DECISION
    assert "rate limit" in second.reason


def test_tool_router_denies_missing_actor_or_tenant_context() -> None:
    router = _router_with_tool(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True))

    decision = router.route(
        ToolInvocation(
            request_id="req-1",
            actor_id="",
            tenant_id="tenant-a",
            tool_name="ticket_lookup",
            action="lookup",
            arguments={"ticket_id": "T-1"},
        )
    )

    assert decision.status == DENY_DECISION
    assert "missing request, actor, or tenant context" in decision.reason


def test_tool_router_redacts_argument_values_in_decisions() -> None:
    router = _router_with_tool(ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True))

    decision = router.route(_invocation(tool_name="ticket_lookup", arguments={"ticket_id": "T-1", "email": "a@b.com"}))

    assert decision.status == ALLOWED_DECISION
    assert decision.sanitized_arguments == {"ticket_id": "[redacted]", "email": "[redacted]"}
