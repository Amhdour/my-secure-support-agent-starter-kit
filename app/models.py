"""Structured request/response and context models for support-agent flow."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence

from retrieval.contracts import RetrievalDocument
from tools.contracts import ToolDecision


@dataclass(frozen=True)
class SessionContext:
    """Session-level metadata carried across requests."""

    session_id: str
    actor_id: str
    tenant_id: str
    channel: str = "support"
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RequestContext:
    """Request-scoped metadata derived from session + inbound request."""

    trace_id: str
    request_id: str
    session_id: str
    actor_id: str
    tenant_id: str
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass(frozen=True)
class SupportAgentRequest:
    """Normalized inbound request payload for orchestration."""

    request_id: str
    user_text: str
    session: SessionContext


@dataclass(frozen=True)
class OrchestrationTrace:
    """Trace information for observability and downstream debugging."""

    policy_checks: Sequence[str]
    retrieved_document_ids: Sequence[str]
    tool_decisions: Sequence[str]


@dataclass(frozen=True)
class SupportAgentResponse:
    """Structured response payload emitted by orchestrator."""

    request_id: str
    session_id: str
    answer_text: str
    status: str
    context: RequestContext
    retrieved_documents: Sequence[RetrievalDocument] = field(default_factory=tuple)
    tool_decisions: Sequence[ToolDecision] = field(default_factory=tuple)
    trace: OrchestrationTrace = field(
        default_factory=lambda: OrchestrationTrace(
            policy_checks=tuple(),
            retrieved_document_ids=tuple(),
            tool_decisions=tuple(),
        )
    )
