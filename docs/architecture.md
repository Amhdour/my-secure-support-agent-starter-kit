# Architecture (Phase 10)

> See `docs/architecture_diagrams.md` for runtime-aligned Mermaid diagrams of system topology, trust boundaries, and core control flows.

## Design Goals
- Policy-first orchestration.
- RAG-first response generation.
- Mediated tool routing with centralized registry and deny-first decisions.
- Secure retrieval boundaries by tenant and registered source.
- Structured telemetry and audit events at critical boundaries.

## Runtime Flow
1. Inbound request is normalized to `SupportAgentRequest`.
2. Session metadata (including tenant boundary) is propagated into `RequestContext`.
3. `PolicyEngine` evaluates `retrieval.search`.
4. `SecureRetrievalService` requests raw results and enforces source registry and trust/provenance checks.
5. `PolicyEngine` evaluates `model.generate`.
6. `LanguageModel` receives `ModelInput` with retrieved context.
7. `PolicyEngine` evaluates `tools.route`.
8. `SecureToolRouter` mediates tool calls with allowlist, forbidden fields/actions, confirmation, and rate limit checks.
9. Router returns explicit decisions: `allow`, `deny`, or `require_confirmation`.
10. `SupportAgentResponse` returns content plus orchestration trace.

## Retrieval Boundary Design
- Retrieval sources must be explicitly registered via `SourceRegistry`.
- Document trust metadata must include source ID, tenant ID, checksum, and ingestion timestamp.
- Documents must include citation-friendly provenance metadata.
- Documents are denied when:
  - source is unregistered or disabled,
  - query tenant differs from source tenant,
  - source is outside `allowed_source_ids`,
  - trust metadata is incomplete/invalid,
  - provenance is missing/invalid.
- Optional `RetrievalFilterHook` hooks allow future policy-driven filtering without coupling retrieval to policy internals.


## Tool Router Design
- Every tool invocation must pass through `SecureToolRouter.route(...)` before execution.
- Router checks, in order: registration, allowlist, forbidden actions, forbidden fields, argument validity, confirmation requirement, and per-tool rate limits.
- `mediate_and_execute(...)` executes only through registry-registered handlers and only when decision is `allow`; direct registry execution attempts without router mediation are denied.
- When uncertain/invalid, router fails closed with an explicit `deny` reason.


## Policy Engine Design
- `load_policy(...)` reads policy JSON, applies environment overrides, validates schema, and returns a restrictive fallback policy on failure.
- `RuntimePolicyEngine.evaluate(...)` enforces runtime behavior for `retrieval.search`, `tools.route`, and `tools.invoke`.
- Retrieval enforcement outputs constraints such as tenant-allowed source IDs and top-k caps by risk tier.
- Tool enforcement outputs constraints for allowlists, forbidden tools/fields, confirmation requirements, and per-tool rate limits.
- Kill switch denies runtime actions immediately; fallback-to-RAG allows no-tool responses when tool routing is denied by policy.


## Audit and Replay Design
- Every request run receives a generated `trace_id` and carries `request_id` across all events.
- Audit events are structured and typed (`request.start/end`, `policy.decision`, `retrieval.decision`, `tool.decision`, `tool.execution_attempt`, `confirmation.required`, `deny.event`, `fallback.event`, `error.event`).
- `JsonlAuditSink` writes one JSON object per line to support launch gate and evidence-pack ingestion.
- Replay artifacts are generated from event timelines and can reconstruct execution order and decisions for investigation.
- Logging intentionally favors decision metadata/counts instead of raw sensitive content.


## Security Eval Harness Design
- Scenarios are defined in JSON with severity, operation type, policy overrides, and explicit pass/fail expectations.
- `SecurityEvalRunner` executes scenarios against real runtime components (policy engine, secure retrieval service, secure tool router, orchestrator) where possible.
- Results are emitted as scenario-level JSONL and summary JSON files for regression tracking.
- Baseline scenarios include prompt injection, indirect injection, malicious retrieval content, cross-tenant access attempts, tool abuse attempts, fallback behavior, and auditability checks.


## Launch Gate Design
- Launch gate evaluates machine-checkable readiness rules over repository/runtime artifacts.
- It verifies mandatory controls, policy artifact validity, retrieval boundary and tool-router enforcement configuration, production kill-switch state, audit/replay evidence minimums, eval pass thresholds/outcome health, and fallback readiness.
- Decisions are transparent and structured as `go`, `conditional_go`, or `no_go`.
- `no_go` is used when blockers exist (missing mandatory controls, invalid/missing policy artifact, or eval threshold failure).
- `conditional_go` is used when critical blockers are absent but residual risks remain (e.g., incomplete audit evidence).


## Evidence Pack Design
- Evidence pack provides reviewer-facing summaries for architecture, controls, policy, evals, telemetry/audit, launch gate, residual risks, and open issues.
- Documentation is intentionally practical and aligned with implemented runtime behavior.
- Integration checks verify required evidence/reviewer/operator docs are present in repository.


## Hardening Notes (Phase 10)
- Retrieval now fails closed if policy constraints are missing/invalid for source allowlists or if retrieval backend raises exceptions.
- Tool routing now requires request/actor/tenant context and redacts argument values in decision payloads.
- Policy engine now denies retrieval when tenant source allowlists are empty and denies tool routing when no tools are allowlisted.
- Launch gate now handles unreadable eval summary artifacts safely as blocking evidence failures.
- Config template launch-gate checks were aligned to implemented check names.
