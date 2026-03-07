# evals/

Reusable AI security eval and red-team harness.

Phase 7 adds:
- Eval runner framework (`SecurityEvalRunner`) that exercises the real runtime path.
<<<<<<< HEAD
- JSON scenario format with severity labels and pass/fail expectations.
=======
- JSON scenario format with severity labels, execution-path labeling (`full_runtime` vs `router_only`), and explicit expectation checks.
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
- Baseline security scenarios covering prompt injection, retrieval abuse, tenant boundaries,
  unsafe disclosure attempts, tool misuse, policy bypass, fallback-to-RAG, and auditability.
- Regression-friendly output artifacts:
  - scenario-level JSONL
<<<<<<< HEAD
  - summary JSON
=======
  - summary JSON with outcome counts (`pass`, `fail`, `expected_fail`, `blocked`, `inconclusive`)
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)

Run example:

```bash
python -m evals.runner
```
