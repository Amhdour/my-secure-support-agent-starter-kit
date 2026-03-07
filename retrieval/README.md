# retrieval/

Secure retrieval abstraction layer with explicit tenant/source boundaries.

Phase 3 adds:
- Source registration model (`SourceRegistration`, `SourceRegistry`).
- Trust and provenance metadata requirements for retrieved documents.
- `SecureRetrievalService` to enforce tenant and source restrictions.
- Optional retrieval filter hooks for future policy-enforcement integration.

Safe defaults:
<<<<<<< HEAD
- Missing trust/provenance metadata fails closed.
- Unregistered, disabled, unauthorized, or cross-tenant sources are denied.
=======
- Missing trust/provenance metadata fails closed when required by policy constraints.
- Unregistered, disabled, malformed, unauthorized, or cross-tenant sources are denied.
- Trust-domain allowlisting is enforced (internal-only by default), quarantining low-trust domains unless explicitly allowlisted by policy.
- Empty source allowlists are denied by default.
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
