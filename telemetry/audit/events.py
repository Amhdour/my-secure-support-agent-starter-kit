"""Audit event helpers."""

from uuid import uuid4

from telemetry.audit.contracts import AuditEvent


def generate_trace_id() -> str:
    """Generate a unique trace id for one orchestrated execution."""

    return f"trace-{uuid4()}"


def create_audit_event(
    *,
    trace_id: str,
    request_id: str,
    actor_id: str,
    tenant_id: str,
    event_type: str,
    payload: dict,
) -> AuditEvent:
    """Create an audit event with generated event id and sanitized payload."""

    return AuditEvent(
        event_id=f"evt-{uuid4()}",
        trace_id=trace_id,
        request_id=request_id,
        actor_id=actor_id,
        tenant_id=tenant_id,
        event_type=event_type,
        event_payload=payload,
    )
