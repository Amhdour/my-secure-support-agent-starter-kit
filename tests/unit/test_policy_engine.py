"""Tests for policy loading, validation, and runtime enforcement behavior."""

import json

from app.modeling import ModelInput
from app.models import SessionContext, SupportAgentRequest
from app.orchestrator import SupportAgentOrchestrator
from policies.engine import RuntimePolicyEngine
from policies.loader import load_policy
from policies.schema import DEFAULT_RESTRICTIVE_POLICY, build_runtime_policy
from retrieval.contracts import DocumentProvenance, RetrievalDocument, SourceTrustMetadata


class FakeRetriever:
    def search(self, query):
        return (
            RetrievalDocument(
                document_id="doc-1",
                content="KB answer",
                trust=SourceTrustMetadata(
                    source_id="kb-main",
                    tenant_id=query.tenant_id,
                    checksum="h1",
                    ingested_at="2026-01-01T00:00:00Z",
                ),
                provenance=DocumentProvenance(
                    citation_id="cite-1",
                    source_id="kb-main",
                    document_uri="kb://doc-1",
                    chunk_id="chunk-1",
                ),
                attributes={},
            ),
        )


class FakeModel:
    def __init__(self) -> None:
        self.inputs: list[ModelInput] = []

    def generate(self, model_input: ModelInput) -> str:
        self.inputs.append(model_input)
        return "draft"


class FakeToolRegistry:
    def list_allowlisted(self):
        from tools.contracts import ToolDescriptor

        return (
            ToolDescriptor(name="ticket_lookup", description="lookup", allowed=True),
            ToolDescriptor(name="account_update", description="update", allowed=True),
        )


class FakeToolRouter:
    def __init__(self, status: str = "allow") -> None:
        self.calls = 0
        self.status = status

    def route(self, invocation):
        from tools.contracts import ToolDecision

        self.calls += 1
        return ToolDecision(
            status=self.status,
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="ok",
            sanitized_arguments=invocation.arguments,
        )


class FakeAuditSink:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _policy_payload() -> dict:
    return {
        "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "medium"},
        "risk_tiers": {
            "medium": {"max_retrieval_top_k": 3, "tools_enabled": True},
            "high": {"max_retrieval_top_k": 1, "tools_enabled": False},
        },
        "retrieval": {
            "allowed_tenants": ["tenant-a"],
            "tenant_allowed_sources": {"tenant-a": ["kb-main"]},
            "require_trust_metadata": True,
            "require_provenance": True,
            "allowed_trust_domains": ["internal"],
        },
        "tools": {
            "allowed_tools": ["ticket_lookup"],
            "forbidden_tools": ["payments_export"],
            "confirmation_required_tools": ["account_update"],
            "forbidden_fields_per_tool": {"ticket_lookup": ["ssn"]},
            "rate_limits_per_tool": {"ticket_lookup": 2},
        },
        "overrides": {"production": {"global": {"kill_switch": True}}},
    }


def test_policy_loading_with_environment_override() -> None:
    payload = _policy_payload()
    policy = build_runtime_policy(environment="production", payload=payload)

    assert policy.valid is True
    assert policy.fallback_to_rag is True


def test_invalid_policy_safe_fail(tmp_path) -> None:
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{ not-json")

    loaded = load_policy(invalid_file, environment="development")

    assert loaded.valid is False
    assert loaded.kill_switch is True
    assert loaded.environment == "development"


def test_missing_policy_safe_fail(tmp_path) -> None:
    missing_file = tmp_path / "missing.json"

    loaded = load_policy(missing_file, environment="development")

    assert loaded.valid is False
    assert loaded.kill_switch is True
    assert "missing" in loaded.validation_errors[0]


def test_restrictive_default_is_fail_closed() -> None:
    assert DEFAULT_RESTRICTIVE_POLICY.valid is False
    assert DEFAULT_RESTRICTIVE_POLICY.kill_switch is True


def test_retrieval_denial_by_policy() -> None:
    policy = build_runtime_policy(environment="dev", payload=_policy_payload())
    engine = RuntimePolicyEngine(policy=policy)

    decision = engine.evaluate(
        request_id="req-1",
        action="retrieval.search",
        context={"tenant_id": "tenant-b"},
    )

    assert decision.allow is False
    assert "tenant" in decision.reason


def test_tool_denial_by_policy() -> None:
    policy = build_runtime_policy(environment="dev", payload=_policy_payload())
    engine = RuntimePolicyEngine(policy=policy)

    decision = engine.evaluate(
        request_id="req-1",
        action="tools.invoke",
        context={"tenant_id": "tenant-a", "tool_name": "unknown_tool", "action": "lookup", "arguments": {}},
    )

    assert decision.allow is False
    assert "allowlisted" in decision.reason


def test_kill_switch_behavior_blocks_orchestration() -> None:
    payload = _policy_payload()
    payload["global"]["kill_switch"] = True
    policy = build_runtime_policy(environment="dev", payload=payload)
    engine = RuntimePolicyEngine(policy=policy)

    model = FakeModel()
    orchestrator = SupportAgentOrchestrator(
        policy_engine=engine,
        retriever=FakeRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=FakeToolRouter(),
        audit_sink=FakeAuditSink(),
    )
    response = orchestrator.run(
        SupportAgentRequest(
            request_id="req-1",
            user_text="help",
            session=SessionContext(session_id="s1", actor_id="a1", tenant_id="tenant-a"),
        )
    )

    assert response.status == "blocked"
    assert model.inputs == []


def test_fallback_to_rag_activation_when_tools_disabled() -> None:
    payload = _policy_payload()
    payload["global"]["default_risk_tier"] = "high"
    payload["risk_tiers"]["high"]["tools_enabled"] = False
    payload["global"]["fallback_to_rag"] = True
    policy = build_runtime_policy(environment="dev", payload=payload)
    engine = RuntimePolicyEngine(policy=policy)

    audit = FakeAuditSink()
    router = FakeToolRouter()
    orchestrator = SupportAgentOrchestrator(
        policy_engine=engine,
        retriever=FakeRetriever(),
        model=FakeModel(),
        tool_registry=FakeToolRegistry(),
        tool_router=router,
        audit_sink=audit,
    )

    response = orchestrator.run(
        SupportAgentRequest(
            request_id="req-2",
            user_text="help",
            session=SessionContext(session_id="s1", actor_id="a1", tenant_id="tenant-a"),
        )
    )

    assert response.status == "ok"
    assert router.calls == 0
    assert any(event.event_type == "fallback.event" for event in audit.events)


def test_policy_change_changes_runtime_tool_routing() -> None:
    allow_payload = _policy_payload()
    deny_payload = _policy_payload()
    deny_payload["tools"]["allowed_tools"] = []

    allow_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=allow_payload))
    deny_engine = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=deny_payload))

    allow_decision = allow_engine.evaluate(request_id="req-allow", action="tools.route", context={"risk_tier": "medium"})
    deny_decision = deny_engine.evaluate(request_id="req-deny", action="tools.route", context={"risk_tier": "medium"})

    assert allow_decision.allow is True
    assert deny_decision.allow is False


def test_policy_change_changes_runtime_retrieval_constraints() -> None:
    payload = _policy_payload()
    payload["retrieval"]["tenant_allowed_sources"] = {"tenant-a": ["kb-main"]}
    engine_a = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=payload))

    payload_b = _policy_payload()
    payload_b["retrieval"]["tenant_allowed_sources"] = {"tenant-a": ["kb-alt"]}
    engine_b = RuntimePolicyEngine(policy=build_runtime_policy(environment="dev", payload=payload_b))

    decision_a = engine_a.evaluate(request_id="req-a", action="retrieval.search", context={"tenant_id": "tenant-a"})
    decision_b = engine_b.evaluate(request_id="req-b", action="retrieval.search", context={"tenant_id": "tenant-a"})

    assert decision_a.constraints["allowed_source_ids"] == ["kb-main"]
    assert decision_b.constraints["allowed_source_ids"] == ["kb-alt"]
