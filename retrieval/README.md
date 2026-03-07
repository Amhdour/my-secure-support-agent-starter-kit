# retrieval/

Secure retrieval abstraction layer with explicit tenant/source boundaries.

Phase 3 adds:
- Source registration model (`SourceRegistration`, `SourceRegistry`).
- Trust and provenance metadata requirements for retrieved documents.
- `SecureRetrievalService` to enforce tenant and source restrictions.
- Optional retrieval filter hooks for future policy-enforcement integration.

Safe defaults:
- Missing trust/provenance metadata fails closed.
- Unregistered, disabled, unauthorized, or cross-tenant sources are denied.
