"""Context helpers for request/session propagation."""

from app.models import RequestContext, SessionContext, SupportAgentRequest


def build_request_context(request: SupportAgentRequest, *, trace_id: str) -> RequestContext:
    """Construct request-scoped context from normalized request envelope."""

    session: SessionContext = request.session
    return RequestContext(
        trace_id=trace_id,
        request_id=request.request_id,
        session_id=session.session_id,
        actor_id=session.actor_id,
        tenant_id=session.tenant_id,
    )
