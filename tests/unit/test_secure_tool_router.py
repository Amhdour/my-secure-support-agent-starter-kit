"""Tests for secure tool routing decisions and enforcement."""

import pytest

from policies.contracts import PolicyDecision
from tools.contracts import (
    ALLOWED_DECISION,
    DENY_DECISION,
    REQUIRE_CONFIRMATION_DECISION,
    DirectToolExecutionDeniedError,
    ToolDescriptor,
    ToolInvocation,
)
from tools.rate_limit import InMemoryToolRateLimiter
from tools.registry import InMemoryToolRegistry
from tools.router import SecureToolRouter


class PolicyAllowInvoke:
    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        assert action == "tools.invoke"
        return PolicyDecision(request_id=request_id, allow=True, reason="allowed", constraints={})


class PolicyDenyInvoke:
    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        return PolicyDecision(request_id=request_id, allow=False, reason="tool denied by policy")


class PolicyRequireConfirmation:
    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        return PolicyDecision(
            request_id=request_id,
            allow=True,
            reason="allowed",
            constraints={"confirmation_required": True},
        )


class PolicyRateLimited:
    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        return PolicyDecision(
            request_id=request_id,
            allow=True,
            reason="allowed",
            constraints={"rate_limit_per_minute": 1},
        )


def _router_with_tool(tool: ToolDescriptor, executor=None, policy_engine=None) -> SecureToolRouter:
    registry = InMemoryToolRegistry()
    registry.register(tool, executor=executor)
    return SecureToolRouter(
        registry=registry,
        rate_limiter=InMemoryToolRateLimiter(),
        policy_engine=policy_engine,
    )


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


def test_allowlisted_tool_execution_when_policy_allows() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
        policy_engine=PolicyAllowInvoke(),
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == ALLOWED_DECISION
    assert result == {"ok": True}


def test_router_fails_closed_without_policy_engine() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert "policy engine unavailable" in decision.reason
    assert result is None


def test_direct_registry_execution_is_blocked_loudly() -> None:
    registry = InMemoryToolRegistry()
    registry.register(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=lambda _: {"ok": True},
    )

    with pytest.raises(DirectToolExecutionDeniedError):
        registry.execute(_invocation(tool_name="ticket_lookup"), execution_secret=object())


def test_unregistered_tool_denial() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=PolicyAllowInvoke(),
    )

    decision = router.route(_invocation(tool_name="missing_tool"))

    assert decision.status == DENY_DECISION
    assert "not registered" in decision.reason


def test_policy_drives_tool_denial_and_blocks_execution() -> None:
    calls: list[str] = []

    def _executor(invocation: ToolInvocation):
        calls.append(invocation.tool_name)
        return {"ok": True}

    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        executor=_executor,
        policy_engine=PolicyDenyInvoke(),
    )

    decision, result = router.mediate_and_execute(_invocation(tool_name="ticket_lookup"))

    assert decision.status == DENY_DECISION
    assert "policy denied" in decision.reason
    assert result is None
    assert calls == []


def test_policy_drives_confirmation_required_flow() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="account_update", description="update", allowed=True),
        policy_engine=PolicyRequireConfirmation(),
    )

    unconfirmed = router.route(_invocation(tool_name="account_update", confirmed=False))
    confirmed = router.route(_invocation(tool_name="account_update", confirmed=True))

    assert unconfirmed.status == REQUIRE_CONFIRMATION_DECISION
    assert confirmed.status == ALLOWED_DECISION


def test_policy_drives_rate_limit_enforcement() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=PolicyRateLimited(),
    )

    first = router.route(_invocation(tool_name="ticket_lookup"))
    second = router.route(_invocation(tool_name="ticket_lookup"))

    assert first.status == ALLOWED_DECISION
    assert second.status == DENY_DECISION
    assert "rate limit" in second.reason


def test_tool_router_denies_missing_actor_or_tenant_context() -> None:
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=PolicyAllowInvoke(),
    )

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
    router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=PolicyAllowInvoke(),
    )

    decision = router.route(_invocation(tool_name="ticket_lookup", arguments={"ticket_id": "T-1", "email": "a@b.com"}))

    assert decision.status == ALLOWED_DECISION
    assert decision.sanitized_arguments == {"ticket_id": "[redacted]", "email": "[redacted]"}


def test_policy_change_changes_runtime_decision() -> None:
    invocation = _invocation(tool_name="ticket_lookup")

    allow_router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=PolicyAllowInvoke(),
    )
    deny_router = _router_with_tool(
        ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
        policy_engine=PolicyDenyInvoke(),
    )

    assert allow_router.route(invocation).status == ALLOWED_DECISION
    assert deny_router.route(invocation).status == DENY_DECISION
