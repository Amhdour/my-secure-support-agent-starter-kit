"""Secure tool router that mediates all tool invocations."""

from dataclasses import dataclass
import json
from typing import Callable, Mapping

from policies.contracts import PolicyEngine
from tools.contracts import (
    ALLOWED_DECISION,
    DENY_DECISION,
    REQUIRE_CONFIRMATION_DECISION,
    ToolDecision,
    ToolInvocation,
    ToolRegistry,
)
from tools.rate_limit import ToolRateLimiter


@dataclass
class SecureToolRouter:
    """Allowlist- and validation-driven tool router.

    This component only decides/mediates; it does not directly expose any path
    for user input to execute tools without checks.
    """

    registry: ToolRegistry
    rate_limiter: ToolRateLimiter
    policy_engine: PolicyEngine | None = None

    def route(self, invocation: ToolInvocation) -> ToolDecision:
        if not invocation.request_id or not invocation.actor_id or not invocation.tenant_id:
            return self._deny(invocation, "missing request, actor, or tenant context")
        if not invocation.tool_name or not invocation.action:
            return self._deny(invocation, "missing tool name or action")

        descriptor = self.registry.get(invocation.tool_name)
        if descriptor is None:
            return self._deny(invocation, "tool is not registered")
        if not descriptor.allowed:
            return self._deny(invocation, "tool is not allowlisted")

        if invocation.action in descriptor.forbidden_actions:
            return self._deny(invocation, "action is forbidden for this tool")

        forbidden_fields = set(descriptor.forbidden_fields)
        violating_fields = sorted(field for field in invocation.arguments if field in forbidden_fields)
        if violating_fields:
            return self._deny(invocation, f"forbidden argument fields: {', '.join(violating_fields)}")

        if not self._valid_arguments(invocation.arguments):
            return self._deny(invocation, "tool arguments failed validation")

        if self.policy_engine is not None:
            try:
                policy_decision = self.policy_engine.evaluate(
                    request_id=invocation.request_id,
                    action="tools.invoke",
                    context={
                        "tenant_id": invocation.tenant_id,
                        "tool_name": invocation.tool_name,
                        "action": invocation.action,
                        "arguments": dict(invocation.arguments),
                    },
                )
            except Exception:
                return self._deny(invocation, "policy evaluation failed")

            if not policy_decision.allow:
                return self._deny(invocation, f"policy denied: {policy_decision.reason}")

            confirmation_required = bool(policy_decision.constraints.get("confirmation_required", False))
            if confirmation_required and not invocation.confirmed:
                return ToolDecision(
                    status=REQUIRE_CONFIRMATION_DECISION,
                    tool_name=invocation.tool_name,
                    action=invocation.action,
                    reason="tool use requires explicit confirmation",
                    sanitized_arguments=self._sanitize_arguments(invocation.arguments),
                )

            policy_rate_limit = policy_decision.constraints.get("rate_limit_per_minute")
            if isinstance(policy_rate_limit, int) and policy_rate_limit > 0:
                key = f"{invocation.tenant_id}:{invocation.actor_id}:{invocation.tool_name}"
                if not self.rate_limiter.allow(key, policy_rate_limit):
                    return self._deny(invocation, "rate limit exceeded")

        if descriptor.confirmation_required and not invocation.confirmed:
            return ToolDecision(
                status=REQUIRE_CONFIRMATION_DECISION,
                tool_name=invocation.tool_name,
                action=invocation.action,
                reason="tool use requires explicit confirmation",
                sanitized_arguments=self._sanitize_arguments(invocation.arguments),
            )

        if descriptor.rate_limit_per_minute is not None:
            key = f"{invocation.tenant_id}:{invocation.actor_id}:{invocation.tool_name}"
            if not self.rate_limiter.allow(key, descriptor.rate_limit_per_minute):
                return self._deny(invocation, "rate limit exceeded")

        return ToolDecision(
            status=ALLOWED_DECISION,
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="tool invocation allowed",
            sanitized_arguments=self._sanitize_arguments(invocation.arguments),
        )

    def mediate_and_execute(
        self,
        invocation: ToolInvocation,
        executor: Callable[[ToolInvocation], Mapping[str, object]],
    ) -> tuple[ToolDecision, Mapping[str, object] | None]:
        """Route first, then execute only if allowed."""

        decision = self.route(invocation)
        if decision.status != ALLOWED_DECISION:
            return decision, None
        return decision, executor(invocation)

    def _deny(self, invocation: ToolInvocation, reason: str) -> ToolDecision:
        return ToolDecision(
            status=DENY_DECISION,
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason=reason,
            sanitized_arguments={},
        )

    def _valid_arguments(self, arguments: Mapping[str, object]) -> bool:
        for key in arguments:
            if not isinstance(key, str) or not key:
                return False
        try:
            json.dumps(arguments)
        except (TypeError, ValueError):
            return False
        return True

    def _sanitize_arguments(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        """Minimize sensitive value exposure while preserving argument shape evidence."""

        return {key: "[redacted]" for key in arguments.keys()}
