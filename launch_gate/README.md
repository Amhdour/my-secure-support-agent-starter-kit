# launch_gate/

Launch-gate readiness evaluator for go / conditional_go / no_go decisions.

Phase 8 adds machine-checkable checks for:
- mandatory control presence
- policy artifact validity
- audit minimum evidence
- eval pass thresholds
- fallback readiness

Outputs are structured and include blockers and residual-risk summaries.
