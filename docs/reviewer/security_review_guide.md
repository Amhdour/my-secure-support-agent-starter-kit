# Security Reviewer Guide

This guide helps reviewers assess implemented controls and evidence quality.

## What to Review First
1. `docs/evidence_pack/` summaries.
2. `policies/bundles/default/policy.json`.
3. `evals/scenarios/security_baseline.json`.
4. `launch_gate/engine.py` readiness logic.

## Key Verification Commands
```bash
pytest
python -m evals.runner
python -m launch_gate.engine
```

## Review Questions
- Are policy decisions enforced in runtime path, not docs-only?
- Are retrieval boundaries explicit for tenant/source?
- Are tool calls mediated and deny-by-default on ambiguity?
- Are denied/fallback/error paths auditable with structured events?
- Does launch gate require actual artifacts before green status?

## Expected Limitations at Scaffold Stage
- Provider integrations are stubs/placeholders.
- No production deployment hardening is claimed.
- Evidence signing/tamper-proofing is not currently implemented.
