# Threat-Model Summary

## Scope
This summary captures the implemented threat posture for the scaffold runtime (not a full STRIDE/LINDDUN dossier).

## Primary Threats Addressed
1. Cross-tenant data access through retrieval.
2. Unsafe tool invocation (unauthorized tool, forbidden fields/actions, unconfirmed sensitive actions).
3. Prompt-injection influence via direct user input and retrieved content.
4. Missing/invalid policy artifacts causing unsafe permissive behavior.
5. Missing evidence causing false-positive launch readiness.

## Implemented Mitigations
- Deny-by-default policy engine and restrictive policy fallback on load/validation failure.
- Retrieval tenant/source/trust/provenance enforcement with fail-closed behavior.
- Centralized tool router mediation and direct-execution guard.
- Structured audit events and replay artifact support.
- Launch-gate checks that require concrete policy/audit/eval/replay evidence.

## Residual Threats (Not Fully Mitigated)
- Supply-chain/runtime risks from future provider integrations.
- Operational misconfiguration risk outside repository controls.
- No cryptographic tamper-evidence for audit/eval artifacts.

## Review Note
See `residual_risks.md` and `open_issues.md` for actively tracked follow-ups.
