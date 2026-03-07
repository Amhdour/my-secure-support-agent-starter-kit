"""Tests for policy loading, validation, and runtime enforcement behavior."""

import json

from app.models import SessionContext, SupportAgentRequest
from app.orchestrator import SupportAgentOrchestrator
from app.modeling import ModelInput
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
    def route(self, invocation):
        from tools.contracts import ToolDecision

        return ToolDecision(
            status="allow",
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


def test_policy_loading_with_environment_override(tmp_path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(_policy_payload()))

    loaded = load_policy(policy_file, environment="production")

    assert loaded.valid is True
    assert loaded.kill_switch is True


def test_invalid_policy_safe_fail(tmp_path) -> None:
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("{ not-json")

    loaded = load_policy(invalid_file, environment="development")

    assert loaded.valid is False
    assert loaded.kill_switch is True
    assert loaded.environment == "development"


<<<<<<< HEAD
=======


def test_missing_policy_safe_fail(tmp_path) -> None:
    missing_file = tmp_path / "missing.json"

    loaded = load_policy(missing_file, environment="development")

    assert loaded.valid is False
    assert loaded.kill_switch is True
    assert "missing" in loaded.validation_errors[0]

>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
def test_retrieval_enforcement_denies_unallowed_tenant() -> None:
    policy = build_runtime_policy(environment="dev", payload=_policy_payload())
    engine = RuntimePolicyEngine(policy=policy)

    decision = engine.evaluate(
        request_id="req-1",
        action="retrieval.search",
        context={"tenant_id": "tenant-b"},
    )

    assert decision.allow is False
    assert "tenant" in decision.reason


<<<<<<< HEAD
=======


def test_retrieval_policy_constraints_include_metadata_and_trust_controls() -> None:
    policy = build_runtime_policy(environment="dev", payload=_policy_payload())
    engine = RuntimePolicyEngine(policy=policy)

    decision = engine.evaluate(
        request_id="req-constraints",
        action="retrieval.search",
        context={"tenant_id": "tenant-a"},
    )

    assert decision.allow is True
    assert decision.constraints.get("require_trust_metadata") is True
    assert decision.constraints.get("require_provenance") is True
    assert decision.constraints.get("allowed_trust_domains") == ["internal"]

>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
def test_tool_enforcement_applies_allowlist_and_forbidden_fields() -> None:
    policy = build_runtime_policy(environment="dev", payload=_policy_payload())
    engine = RuntimePolicyEngine(policy=policy)

    denied_tool = engine.evaluate(
        request_id="req-1",
        action="tools.invoke",
        context={"tenant_id": "tenant-a", "tool_name": "unknown_tool", "action": "lookup", "arguments": {}},
    )
    forbidden_field = engine.evaluate(
        request_id="req-1",
        action="tools.invoke",
        context={
            "tenant_id": "tenant-a",
            "tool_name": "ticket_lookup",
            "action": "lookup",
            "arguments": {"ssn": "x"},
        },
    )

    assert denied_tool.allow is False
    assert forbidden_field.allow is False


def test_kill_switch_blocks_orchestration() -> None:
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


def test_fallback_to_rag_when_tools_disabled_for_risk_tier() -> None:
    payload = _policy_payload()
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
            request_id="req-2",
            user_text="help",
            session=SessionContext(session_id="s1", actor_id="a1", tenant_id="tenant-a"),
        )
    )

    assert response.status == "ok"
    # medium tier allows tools, so force high tier evaluation path check directly
    high_decision = engine.evaluate(
        request_id="req-2",
        action="tools.route",
        context={"risk_tier": "high"},
    )
    assert high_decision.allow is False
    assert high_decision.fallback_to_rag is True


def test_retrieval_denied_when_no_sources_allowlisted() -> None:
    payload = _policy_payload()
    payload["retrieval"]["tenant_allowed_sources"] = {"tenant-a": []}
    policy = build_runtime_policy(environment="dev", payload=payload)
    engine = RuntimePolicyEngine(policy=policy)

    decision = engine.evaluate(request_id="req-3", action="retrieval.search", context={"tenant_id": "tenant-a"})

    assert decision.allow is False
    assert "allowlisted retrieval sources" in decision.reason


def test_tools_route_denied_when_no_tools_allowlisted() -> None:
    payload = _policy_payload()
    payload["tools"]["allowed_tools"] = []
    policy = build_runtime_policy(environment="dev", payload=payload)
    engine = RuntimePolicyEngine(policy=policy)

    decision = engine.evaluate(request_id="req-4", action="tools.route", context={"risk_tier": "medium"})

    assert decision.allow is False
    assert decision.fallback_to_rag is True
