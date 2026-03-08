"""Policy-as-code runtime engine enforcing retrieval/tool constraints."""

from dataclasses import dataclass
from typing import Mapping

from policies.contracts import PolicyDecision, PolicyEngine
from policies.schema import RiskTierPolicy, RuntimePolicy


@dataclass
class RuntimePolicyEngine(PolicyEngine):
    """Evaluates policy decisions that affect runtime behavior."""

    policy: RuntimePolicy

    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        risk_tier, tier = self._resolve_risk_tier(context)

        if not self.policy.valid:
            return PolicyDecision(
                request_id=request_id,
                allow=False,
                reason="invalid policy: fail closed",
                risk_tier=risk_tier,
                fallback_to_rag=False,
            )

        if self.policy.kill_switch:
            return PolicyDecision(
                request_id=request_id,
                allow=False,
                reason="kill switch enabled",
                risk_tier=risk_tier,
                fallback_to_rag=False,
            )

        if action == "retrieval.search":
            tenant_id = str(context.get("tenant_id", ""))
            if not tenant_id:
                return PolicyDecision(request_id=request_id, allow=False, reason="missing tenant", risk_tier=risk_tier)
            if self.policy.retrieval.allowed_tenants and tenant_id not in self.policy.retrieval.allowed_tenants:
                return PolicyDecision(request_id=request_id, allow=False, reason="tenant not allowed", risk_tier=risk_tier)

            allowed_sources = self.policy.retrieval.tenant_allowed_sources.get(tenant_id, tuple())
            if len(allowed_sources) == 0:
                return PolicyDecision(
                    request_id=request_id,
                    allow=False,
                    reason="no allowlisted retrieval sources for tenant",
                    risk_tier=risk_tier,
                )

            constraints = {
                "allowed_source_ids": list(allowed_sources),
                "top_k_cap": tier.max_retrieval_top_k,
                "require_trust_metadata": self.policy.retrieval.require_trust_metadata,
                "require_provenance": self.policy.retrieval.require_provenance,
                "allowed_trust_domains": list(self.policy.retrieval.allowed_trust_domains),
            }
            return PolicyDecision(
                request_id=request_id,
                allow=True,
                reason="retrieval allowed",
                risk_tier=risk_tier,
                constraints=constraints,
            )

        if action == "model.generate":
            return PolicyDecision(
                request_id=request_id,
                allow=True,
                reason="model generation allowed",
                risk_tier=risk_tier,
            )

        if action == "tools.route":
            if not tier.tools_enabled:
                return PolicyDecision(
                    request_id=request_id,
                    allow=False,
                    reason="tools disabled for risk tier",
                    risk_tier=risk_tier,
                    fallback_to_rag=self.policy.fallback_to_rag,
                )
            if len(self.policy.tools.allowed_tools) == 0:
                return PolicyDecision(
                    request_id=request_id,
                    allow=False,
                    reason="no allowlisted tools configured",
                    risk_tier=risk_tier,
                    fallback_to_rag=self.policy.fallback_to_rag,
                )
            constraints = {
                "allowed_tools": list(self.policy.tools.allowed_tools),
                "forbidden_tools": list(self.policy.tools.forbidden_tools),
                "confirmation_required_tools": list(self.policy.tools.confirmation_required_tools),
                "forbidden_fields_per_tool": {
                    tool: list(fields)
                    for tool, fields in self.policy.tools.forbidden_fields_per_tool.items()
                },
                "rate_limits_per_tool": dict(self.policy.tools.rate_limits_per_tool),
            }
            return PolicyDecision(
                request_id=request_id,
                allow=True,
                reason="tool routing allowed",
                risk_tier=risk_tier,
                constraints=constraints,
            )

        if action == "tools.invoke":
            tenant_id = str(context.get("tenant_id", ""))
            tool_name = str(context.get("tool_name", ""))
            action_name = str(context.get("action", ""))
            arguments = context.get("arguments", {})

            if not tenant_id:
                return PolicyDecision(request_id=request_id, allow=False, reason="missing tenant", risk_tier=risk_tier)
            if not tool_name or not action_name:
                return PolicyDecision(request_id=request_id, allow=False, reason="missing tool name or action", risk_tier=risk_tier)
            if not isinstance(arguments, Mapping):
                return PolicyDecision(request_id=request_id, allow=False, reason="tool arguments must be an object", risk_tier=risk_tier)

            if tool_name in self.policy.tools.forbidden_tools:
                return PolicyDecision(request_id=request_id, allow=False, reason="tool forbidden", risk_tier=risk_tier)
            if self.policy.tools.allowed_tools and tool_name not in self.policy.tools.allowed_tools:
                return PolicyDecision(request_id=request_id, allow=False, reason="tool not allowlisted by policy", risk_tier=risk_tier)

            forbidden_fields = self.policy.tools.forbidden_fields_per_tool.get(tool_name, tuple())
            for field in forbidden_fields:
                if field in arguments:
                    return PolicyDecision(
                        request_id=request_id,
                        allow=False,
                        reason=f"forbidden field in arguments: {field}",
                        risk_tier=risk_tier,
                    )

            constraints = {
                "confirmation_required": tool_name in self.policy.tools.confirmation_required_tools,
                "rate_limit_per_minute": self.policy.tools.rate_limits_per_tool.get(tool_name),
                "tool_action": action_name,
            }
            return PolicyDecision(
                request_id=request_id,
                allow=True,
                reason="tool invocation allowed",
                risk_tier=risk_tier,
                constraints=constraints,
            )

        return PolicyDecision(
            request_id=request_id,
            allow=False,
            reason=f"unknown policy action: {action}",
            risk_tier=risk_tier,
        )

    def _resolve_risk_tier(self, context: dict) -> tuple[str, RiskTierPolicy]:
        requested = str(context.get("risk_tier", self.policy.default_risk_tier))
        fallback_tier = self.policy.risk_tiers.get(self.policy.default_risk_tier)
        if fallback_tier is None:
            fallback_tier = RiskTierPolicy(max_retrieval_top_k=1, tools_enabled=False)
        return requested, self.policy.risk_tiers.get(requested, fallback_tier)
