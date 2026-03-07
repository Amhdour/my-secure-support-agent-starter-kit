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
- Audit minimum evidence present.
- Eval threshold met.
- Fallback readiness present.

## Evidence Expectations
Launch gate should not be treated as green without real artifacts (policy, audit, eval outputs).
