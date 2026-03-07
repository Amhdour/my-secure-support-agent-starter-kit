"""Audit contracts for structured telemetry and replay artifacts."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Protocol


REQUEST_START_EVENT = "request.start"
REQUEST_END_EVENT = "request.end"
RETRIEVAL_DECISION_EVENT = "retrieval.decision"
TOOL_DECISION_EVENT = "tool.decision"
TOOL_EXECUTION_ATTEMPT_EVENT = "tool.execution_attempt"
POLICY_DECISION_EVENT = "policy.decision"
CONFIRMATION_REQUIRED_EVENT = "confirmation.required"
DENY_EVENT = "deny.event"
FALLBACK_EVENT = "fallback.event"
ERROR_EVENT = "error.event"


@dataclass(frozen=True)
class AuditEvent:
    """Structured audit event for investigation and replay."""

    event_id: str
    trace_id: str
    request_id: str
    actor_id: str
    tenant_id: str
    event_type: str
    event_payload: Mapping[str, object]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None:
        """Emit an audit event to the configured sink."""
        ...
