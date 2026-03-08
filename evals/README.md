# evals/

Reusable AI security eval and red-team harness.

Phase 7 adds:
- Eval runner framework (`SecurityEvalRunner`) that exercises the real runtime path.
- JSON scenario format with severity labels, execution-path labeling (`full_runtime` vs `router_only`), and explicit expectation checks.
- Baseline security scenarios covering prompt injection, retrieval abuse, tenant boundaries,
  unsafe disclosure attempts, tool misuse, policy bypass, fallback-to-RAG, and auditability.
- Regression-friendly output artifacts:
  - scenario-level JSONL
  - summary JSON with outcome counts (`pass`, `fail`, `expected_fail`, `blocked`, `inconclusive`)

Run example:

```bash
python -m evals.runner
```
