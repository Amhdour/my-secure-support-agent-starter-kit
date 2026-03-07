# policies/

Policy-as-code runtime controls for retrieval and tool mediation.

Phase 5 adds:
- Runtime schema (`policies/schema.py`) with restrictive defaults.
- Policy loader (`policies/loader.py`) with environment-specific overrides.
- Runtime engine (`policies/engine.py`) enforcing:
  - retrieval tenant/source restrictions,
  - allowed/forbidden tools,
  - confirmation-required tools,
  - forbidden fields,
  - per-tool rate-limit constraints,
  - risk-tier behavior,
  - kill switch and fallback-to-RAG.

Safe defaults:
- Missing/invalid policy fails closed (`DEFAULT_RESTRICTIVE_POLICY`).
- Unknown actions deny by default.
