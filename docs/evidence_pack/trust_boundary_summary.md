# Trust-Boundary Summary

## Implemented Trust Boundaries

### Tenant Boundary
- `SessionContext.tenant_id` is propagated into orchestration and policy/retrieval/tool decisions.
- Retrieval denies cross-tenant access by enforcing `query.tenant_id` against registered source tenant and document trust metadata tenant.
- Policy runtime denies retrieval when tenant is missing/not allowlisted or tenant has no allowlisted sources.

### Source Boundary
- Retrieval accepts only explicitly registered sources (`SourceRegistry`).
- Retrieval enforces source allowlists from policy constraints (`allowed_source_ids`).
- Disabled/malformed/unregistered sources are denied.

### Trust & Provenance Boundary
- Retrieval can require trust metadata (`source_id`, `tenant_id`, `checksum`, `ingested_at`) and provenance (`citation_id`, `document_uri`, `chunk_id`).
- Retrieval enforces trust-domain allowlisting (`allowed_trust_domains`), internal-only by default unless policy broadens it.

### Tool Boundary
- Tool invocation decisions pass through `SecureToolRouter` with policy checks, forbidden tools/fields/actions, confirmation checks, and rate limits.
- Direct registry execution without router mediation is blocked.

## Non-Claims
- No external identity provider integration is implemented in this scaffold.
- No network-level segmentation controls are implemented here; this repo enforces application-layer boundaries.
