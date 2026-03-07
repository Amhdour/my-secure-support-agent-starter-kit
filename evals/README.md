# evals/

Reusable AI security eval and red-team harness.

Phase 7 adds:
- Eval runner framework (`SecurityEvalRunner`) that exercises the real runtime path.
- JSON scenario format with severity labels and pass/fail expectations.
- Baseline security scenarios covering prompt injection, retrieval abuse, tenant boundaries,
  unsafe disclosure attempts, tool misuse, policy bypass, fallback-to-RAG, and auditability.
- Regression-friendly output artifacts:
  - scenario-level JSONL
  - summary JSON

Run example:

```bash
python -m evals.runner
```
