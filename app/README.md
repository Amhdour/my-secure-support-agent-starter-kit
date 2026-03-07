# app/

Application orchestration layer.

Current Phase 2 responsibilities:
- Define structured request/response/context models.
- Build request context from session metadata.
- Orchestrate policy checks, retrieval, model generation, and tool decision routing.
- Emit audit events for blocked/completed orchestration states.

This layer remains business-logic-free and provider-agnostic.
