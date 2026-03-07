# Tool Authorization Summary

## Implemented Controls
- Centralized policy-aware mediation via `SecureToolRouter`.
- Allow/deny/require_confirmation decisions.
- Forbidden tools, forbidden fields, and forbidden actions enforcement.
- Per-tool rate limits and confirmation-required enforcement.
- Direct tool execution guard in registry (`DirectToolExecutionDeniedError`).

## Evidence Touchpoints
- Runtime implementation: `tools/router.py`, `tools/registry.py`
- Policy constraints: `policies/engine.py`, `policies/schema.py`
- Tests: `tests/unit/test_secure_tool_router.py`

## Reviewer Checks
- Confirm `allowed_tools` is explicit and minimal.
- Confirm sensitive-field deny rules are present (`forbidden_fields_per_tool`).
- Confirm router-mediated path is used for all tool execution flows.
