# launch_gate/

Launch-gate readiness evaluator for go / conditional_go / no_go decisions.

Phase 8 adds machine-checkable checks for:
- mandatory control presence
- policy artifact validity
<<<<<<< HEAD
- audit minimum evidence
- eval pass thresholds
=======
- retrieval boundary configuration validity
- tool-router enforcement configuration validity
- production kill-switch state
- audit minimum evidence
- replay artifact presence/validity
- eval pass thresholds and outcome health
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
- fallback readiness

Outputs are structured and include blockers and residual-risk summaries.
