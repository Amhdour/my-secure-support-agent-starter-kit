"""Policy schema types and validation helpers."""

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class RetrievalPolicy:
    allowed_tenants: tuple[str, ...] = tuple()
    tenant_allowed_sources: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    require_trust_metadata: bool = True
    require_provenance: bool = True
<<<<<<< HEAD
=======
    allowed_trust_domains: tuple[str, ...] = ("internal",)
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)


@dataclass(frozen=True)
class ToolPolicy:
    allowed_tools: tuple[str, ...] = tuple()
    forbidden_tools: tuple[str, ...] = tuple()
    confirmation_required_tools: tuple[str, ...] = tuple()
    forbidden_fields_per_tool: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    rate_limits_per_tool: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskTierPolicy:
    max_retrieval_top_k: int = 5
    tools_enabled: bool = True


@dataclass(frozen=True)
class RuntimePolicy:
    environment: str
    valid: bool
    kill_switch: bool
    fallback_to_rag: bool
    default_risk_tier: str
    risk_tiers: Mapping[str, RiskTierPolicy]
    retrieval: RetrievalPolicy
    tools: ToolPolicy
    validation_errors: tuple[str, ...] = tuple()


def restrictive_policy(*, environment: str, reason: str) -> RuntimePolicy:
    """Build a restrictive fail-safe policy object."""

    return RuntimePolicy(
        environment=environment,
        valid=False,
        kill_switch=True,
        fallback_to_rag=False,
        default_risk_tier="high",
        risk_tiers={"high": RiskTierPolicy(max_retrieval_top_k=1, tools_enabled=False)},
        retrieval=RetrievalPolicy(),
        tools=ToolPolicy(),
        validation_errors=(reason,),
    )


DEFAULT_RESTRICTIVE_POLICY = restrictive_policy(environment="unknown", reason="missing or invalid policy")


def _tuple_of_strings(value: Any, *, field_name: str, errors: list[str]) -> tuple[str, ...]:
    if value is None:
        return tuple()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        errors.append(f"{field_name} must be a list[str]")
        return tuple()
    return tuple(value)


def build_runtime_policy(*, environment: str, payload: Mapping[str, Any]) -> RuntimePolicy:
    errors: list[str] = []
    if not isinstance(payload, Mapping):
        return restrictive_policy(environment=environment, reason="policy payload must be an object")

    global_cfg = payload.get("global", {})
    retrieval_cfg = payload.get("retrieval", {})
    tools_cfg = payload.get("tools", {})
    risk_cfg = payload.get("risk_tiers", {})

    if not isinstance(global_cfg, Mapping):
        errors.append("global must be an object")
        global_cfg = {}
    if not isinstance(retrieval_cfg, Mapping):
        errors.append("retrieval must be an object")
        retrieval_cfg = {}
    if not isinstance(tools_cfg, Mapping):
        errors.append("tools must be an object")
        tools_cfg = {}
    if not isinstance(risk_cfg, Mapping):
        errors.append("risk_tiers must be an object")
        risk_cfg = {}

    default_risk_tier = global_cfg.get("default_risk_tier", "high")
    if not isinstance(default_risk_tier, str):
        errors.append("global.default_risk_tier must be a string")
        default_risk_tier = "high"

    kill_switch = bool(global_cfg.get("kill_switch", False))
    fallback_to_rag = bool(global_cfg.get("fallback_to_rag", False))

    allowed_tenants = _tuple_of_strings(
        retrieval_cfg.get("allowed_tenants", []),
        field_name="retrieval.allowed_tenants",
        errors=errors,
    )
    tenant_allowed_sources: dict[str, tuple[str, ...]] = {}
    raw_tenant_sources = retrieval_cfg.get("tenant_allowed_sources", {})
    if isinstance(raw_tenant_sources, Mapping):
        for tenant, sources in raw_tenant_sources.items():
            if not isinstance(tenant, str):
                errors.append("retrieval.tenant_allowed_sources keys must be strings")
                continue
            tenant_allowed_sources[tenant] = _tuple_of_strings(
                sources,
                field_name=f"retrieval.tenant_allowed_sources.{tenant}",
                errors=errors,
            )
    else:
        errors.append("retrieval.tenant_allowed_sources must be an object")

    retrieval = RetrievalPolicy(
        allowed_tenants=allowed_tenants,
        tenant_allowed_sources=tenant_allowed_sources,
        require_trust_metadata=bool(retrieval_cfg.get("require_trust_metadata", True)),
        require_provenance=bool(retrieval_cfg.get("require_provenance", True)),
<<<<<<< HEAD
=======
        allowed_trust_domains=_tuple_of_strings(
            retrieval_cfg.get("allowed_trust_domains", ["internal"]),
            field_name="retrieval.allowed_trust_domains",
            errors=errors,
        ),
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
    )

    allowed_tools = _tuple_of_strings(tools_cfg.get("allowed_tools", []), field_name="tools.allowed_tools", errors=errors)
    forbidden_tools = _tuple_of_strings(tools_cfg.get("forbidden_tools", []), field_name="tools.forbidden_tools", errors=errors)
    confirmation_required_tools = _tuple_of_strings(
        tools_cfg.get("confirmation_required_tools", []),
        field_name="tools.confirmation_required_tools",
        errors=errors,
    )

    forbidden_fields_per_tool: dict[str, tuple[str, ...]] = {}
    raw_forbidden_fields = tools_cfg.get("forbidden_fields_per_tool", {})
    if isinstance(raw_forbidden_fields, Mapping):
        for tool, fields in raw_forbidden_fields.items():
            if not isinstance(tool, str):
                errors.append("tools.forbidden_fields_per_tool keys must be strings")
                continue
            forbidden_fields_per_tool[tool] = _tuple_of_strings(
                fields,
                field_name=f"tools.forbidden_fields_per_tool.{tool}",
                errors=errors,
            )
    else:
        errors.append("tools.forbidden_fields_per_tool must be an object")

    rate_limits_per_tool: dict[str, int] = {}
    raw_limits = tools_cfg.get("rate_limits_per_tool", {})
    if isinstance(raw_limits, Mapping):
        for tool, limit in raw_limits.items():
            if not isinstance(tool, str) or not isinstance(limit, int) or limit <= 0:
                errors.append(f"tools.rate_limits_per_tool.{tool} must be a positive int")
                continue
            rate_limits_per_tool[tool] = limit
    else:
        errors.append("tools.rate_limits_per_tool must be an object")

    tools = ToolPolicy(
        allowed_tools=allowed_tools,
        forbidden_tools=forbidden_tools,
        confirmation_required_tools=confirmation_required_tools,
        forbidden_fields_per_tool=forbidden_fields_per_tool,
        rate_limits_per_tool=rate_limits_per_tool,
    )

    risk_tiers: dict[str, RiskTierPolicy] = {}
    for tier_name, tier_cfg in risk_cfg.items():
        if not isinstance(tier_name, str) or not isinstance(tier_cfg, Mapping):
            errors.append("risk_tiers entries must be object values with string keys")
            continue
        max_top_k = tier_cfg.get("max_retrieval_top_k", 5)
        tools_enabled = tier_cfg.get("tools_enabled", True)
        if not isinstance(max_top_k, int) or max_top_k <= 0:
            errors.append(f"risk_tiers.{tier_name}.max_retrieval_top_k must be positive int")
            max_top_k = 1
        risk_tiers[tier_name] = RiskTierPolicy(
            max_retrieval_top_k=max_top_k,
            tools_enabled=bool(tools_enabled),
        )

    if default_risk_tier not in risk_tiers:
        risk_tiers[default_risk_tier] = RiskTierPolicy(max_retrieval_top_k=5, tools_enabled=False)

    return RuntimePolicy(
        environment=environment,
        valid=len(errors) == 0,
        kill_switch=kill_switch,
        fallback_to_rag=fallback_to_rag,
        default_risk_tier=default_risk_tier,
        risk_tiers=risk_tiers,
        retrieval=retrieval,
        tools=tools,
        validation_errors=tuple(errors),
    )
