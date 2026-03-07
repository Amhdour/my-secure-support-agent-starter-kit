# Retrieval Security Summary

## Implemented Controls
- Tenant allowlists and tenant-to-source allowlists in runtime policy.
- Cross-tenant denial and unauthorized-source denial in `SecureRetrievalService`.
- Required trust metadata and provenance checks (when policy requires).
- Trust-domain allowlisting (internal-only default unless policy override).
- Fail-closed behavior on policy-evaluation or backend retrieval exceptions.

## Evidence Touchpoints
- Runtime implementation: `retrieval/service.py`
- Policy constraints: `policies/engine.py`, `policies/schema.py`
- Tests: `tests/unit/test_secure_retrieval_service.py`

## Reviewer Checks
- Confirm tenant/source allowlists are non-empty for intended tenants.
- Confirm `require_trust_metadata` and `require_provenance` are enabled for production policy.
- Confirm `allowed_trust_domains` is intentional and not over-broad.
