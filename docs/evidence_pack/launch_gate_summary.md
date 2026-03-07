# Launch Gate Summary

## Command
```bash
python -m launch_gate.engine
```

## Outcomes
- `go`: all checks passed.
- `conditional_go`: no critical blockers, but residual risks remain.
- `no_go`: one or more critical blockers detected.

## Current Gate Checks
- Mandatory control files present.
- Policy artifact present and valid.
- Retrieval boundary consistency (tenant allowlists aligned with tenant source allowlists + trust/provenance requirements).
- Tool-router enforcement configuration present (allowlists, forbidden fields, rate limits).
- Production kill-switch state acceptable (disabled).
- Audit minimum evidence present.
- Replay artifact evidence present/valid when required.
- Eval threshold and outcome health met.
- Fallback readiness present.

## Evidence Expectations
Launch gate should not be treated as green without real artifacts (policy, audit, eval outputs).
