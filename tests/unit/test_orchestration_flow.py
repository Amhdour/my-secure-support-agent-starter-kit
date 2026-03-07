"""Tests for policy-aware orchestration and context propagation."""

from app.models import SessionContext, SupportAgentRequest
from app.orchestrator import SupportAgentOrchestrator
from app.modeling import ModelInput
from policies.contracts import PolicyDecision
from retrieval.contracts import DocumentProvenance, RetrievalDocument, SourceTrustMetadata
from tools.contracts import ToolDecision, ToolDescriptor


class FakePolicyEngine:
    def __init__(self, denied_actions: set[str] | None = None) -> None:
        self.denied_actions = denied_actions or set()
        self.calls: list[str] = []

    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        self.calls.append(action)
        allow = action not in self.denied_actions
        reason = "allowed" if allow else f"{action} denied"
        return PolicyDecision(request_id=request_id, allow=allow, reason=reason)


class FakeRetriever:
    def search(self, query):
        return (
            RetrievalDocument(
                document_id="doc-1",
                content="Reset via profile page.",
                trust=SourceTrustMetadata(
                    source_id="kb",
                    tenant_id="tenant-a",
                    checksum="hash-1",
                    ingested_at="2026-01-01T00:00:00Z",
                ),
                provenance=DocumentProvenance(
                    citation_id="cite-1",
                    source_id="kb",
                    document_uri="kb://reset",
                    chunk_id="chunk-1",
                ),
                attributes={"topic": "password"},
            ),
            RetrievalDocument(
                document_id="doc-2",
                content="Enable MFA for security.",
                trust=SourceTrustMetadata(
                    source_id="kb",
                    tenant_id="tenant-a",
                    checksum="hash-2",
                    ingested_at="2026-01-01T00:00:00Z",
                ),
                provenance=DocumentProvenance(
                    citation_id="cite-2",
                    source_id="kb",
                    document_uri="kb://mfa",
                    chunk_id="chunk-2",
                ),
                attributes={"topic": "mfa"},
            ),
        )


class FakeModel:
    def __init__(self) -> None:
        self.inputs: list[ModelInput] = []

    def generate(self, model_input: ModelInput) -> str:
        self.inputs.append(model_input)
        return "Here are the next support steps."


class FakeToolRegistry:
    def list_allowlisted(self):
        return (ToolDescriptor(name="ticket_lookup", description="Lookup ticket metadata", allowed=True),)


class FakeToolRouter:
    def __init__(self) -> None:
        self.calls = 0

    def route(self, invocation):
        self.calls += 1
        return ToolDecision(
            status="allow",
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="Could help validate account state.",
            sanitized_arguments=invocation.arguments,
        )


class FakeAuditSink:
    def __init__(self) -> None:
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _build_request() -> SupportAgentRequest:
    return SupportAgentRequest(
        request_id="req-123",
        user_text="I cannot reset my password",
        session=SessionContext(session_id="sess-9", actor_id="user-7", tenant_id="tenant-a", channel="chat"),
    )


def test_orchestration_happy_path_routes_through_rag_and_tool_decision() -> None:
    policy = FakePolicyEngine()
    model = FakeModel()
    router = FakeToolRouter()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=policy,
        retriever=FakeRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=router,
        audit_sink=audit,
    )

    response = orchestrator.run(_build_request())

    assert response.status == "ok"
    assert response.context.session_id == "sess-9"
    assert response.context.actor_id == "user-7"
    assert response.context.tenant_id == "tenant-a"
    assert len(response.retrieved_documents) == 2
    assert response.trace.retrieved_document_ids == ("doc-1", "doc-2")
    assert response.tool_decisions[0].tool_name == "ticket_lookup"
    assert policy.calls == ["retrieval.search", "model.generate", "tools.route"]
    assert router.calls == 1
    assert model.inputs[0].metadata["session_id"] == "sess-9"
    event_types = [event.event_type for event in audit.events]
    assert "request.start" in event_types
    assert "request.end" in event_types
    assert "policy.decision" in event_types
    assert all(event.trace_id == response.context.trace_id for event in audit.events)


def test_orchestration_blocks_when_retrieval_policy_denied() -> None:
    policy = FakePolicyEngine(denied_actions={"retrieval.search"})
    model = FakeModel()
    router = FakeToolRouter()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=policy,
        retriever=FakeRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=router,
        audit_sink=audit,
    )

    response = orchestrator.run(_build_request())

    assert response.status == "blocked"
    assert response.retrieved_documents == ()
    assert response.tool_decisions == ()
    assert router.calls == 0
    assert model.inputs == []
    event_types = [event.event_type for event in audit.events]
    assert "deny.event" in event_types
    assert "request.end" in event_types
<<<<<<< HEAD
=======


class FakeDenyToolRouter:
    def route(self, invocation):
        return ToolDecision(
            status="deny",
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="tool denied for safety",
            sanitized_arguments={},
        )


class FakeConfirmToolRouter:
    def route(self, invocation):
        return ToolDecision(
            status="require_confirmation",
            tool_name=invocation.tool_name,
            action=invocation.action,
            reason="confirmation required",
            sanitized_arguments={},
        )


def test_orchestration_logs_denied_tool_calls() -> None:
    policy = FakePolicyEngine()
    model = FakeModel()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=policy,
        retriever=FakeRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=FakeDenyToolRouter(),
        audit_sink=audit,
    )

    response = orchestrator.run(_build_request())

    assert response.status == "ok"
    deny_events = [event for event in audit.events if event.event_type == "deny.event"]
    assert deny_events
    assert any(event.event_payload.get("stage") == "tool.route" for event in deny_events)


def test_orchestration_preserves_confirmation_required_flow() -> None:
    policy = FakePolicyEngine()
    model = FakeModel()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=policy,
        retriever=FakeRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=FakeConfirmToolRouter(),
        audit_sink=audit,
    )

    response = orchestrator.run(_build_request())

    assert response.status == "ok"
    assert response.tool_decisions[0].status == "require_confirmation"
    confirmation_events = [event for event in audit.events if event.event_type == "confirmation.required"]
    assert confirmation_events


class FakeFallbackToolPolicyEngine(FakePolicyEngine):
    def evaluate(self, request_id: str, action: str, context: dict) -> PolicyDecision:
        self.calls.append(action)
        if action == "tools.route":
            return PolicyDecision(
                request_id=request_id,
                allow=False,
                reason="tools disabled for risk tier",
                fallback_to_rag=True,
            )
        return PolicyDecision(request_id=request_id, allow=True, reason="allowed")


def test_orchestration_activates_fallback_to_rag_when_tools_route_denied_with_fallback() -> None:
    policy = FakeFallbackToolPolicyEngine()
    model = FakeModel()
    router = FakeToolRouter()
    audit = FakeAuditSink()

    orchestrator = SupportAgentOrchestrator(
        policy_engine=policy,
        retriever=FakeRetriever(),
        model=model,
        tool_registry=FakeToolRegistry(),
        tool_router=router,
        audit_sink=audit,
    )

    response = orchestrator.run(_build_request())

    assert response.status == "ok"
    assert response.tool_decisions == ()
    event_types = [event.event_type for event in audit.events]
    assert "fallback.event" in event_types
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
