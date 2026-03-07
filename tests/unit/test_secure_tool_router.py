"""Tests for secure tool routing decisions and enforcement."""

<<<<<<< HEAD
=======
import pytest

>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
from tools.contracts import (
    ALLOWED_DECISION,
    DENY_DECISION,
    REQUIRE_CONFIRMATION_DECISION,
<<<<<<< HEAD
=======
    DirectToolExecutionDeniedError,
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
    ToolDescriptor,
    ToolInvocation,
)
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


<<<<<<< HEAD
def _router_with_tool(tool: ToolDescriptor) -> SecureToolRouter:
    registry = InMemoryToolRegistry()
    registry.register(tool)
=======
def _router_with_tool(tool: ToolDescriptor, executor=None) -> SecureToolRouter:
    registry = InMemoryToolRegistry()
    registry.register(tool, executor=executor)
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
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
<<<<<<< HEAD
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True)
    )

    decision, result = router.mediate_and_execute(
        _invocation(tool_name="ticket_lookup"),
        executor=lambda _: {"ok": True},
    )

=======
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
    assert decision.status == ALLOWED_DECISION
    assert result == {"ok": True}


<<<<<<< HEAD
=======
def test_direct_registry_execution_is_blocked_loudly() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )

    with pytest.raises(DirectToolExecutionDeniedError):
        registry.execute(_invocation(tool_name="ticket_lookup"), execution_secret=object())


>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
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
<<<<<<< HEAD
=======


def test_router_executes_registered_executor_once_for_allowed_calls() -> None:
    calls: list[str] = []

    def _executor(invocation: ToolInvocation):
        calls.append(invocation.tool_name)
        return {"status": "ok"}

    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=_executor,
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == ALLOWED_DECISION
    assert result == {"status": "ok"}
    assert calls == ["ticket_lookup"]


class DenyInvokePolicyEngine:
    def evaluate(self, request_id: str, action: str, context: dict):
        from policies.contracts import PolicyDecision

        return PolicyDecision(request_id=request_id, allow=False, reason="tool denied by policy")


def test_tool_denial_by_policy_blocks_execution() -> None:
    calls: list[str] = []

    def _executor(invocation: ToolInvocation):
        calls.append(invocation.tool_name)
        return {"ok": True}

    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=_executor,
    )
    router = SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=DenyInvokePolicyEngine(),
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert "policy denied" in decision.reason
    assert result is None
    assert calls == []
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
