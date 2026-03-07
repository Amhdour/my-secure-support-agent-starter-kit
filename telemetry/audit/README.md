# telemetry/audit/

Structured audit telemetry, JSONL sinks, and replay artifact tooling.

Phase 6 adds:
- Trace-aware structured event contracts for investigation and trust.
- Event types for request lifecycle, policy/retrieval/tool decisions, fallback, denies, confirmations, and errors.
- JSONL output sink for launch-gate/evidence-pack consumption.
- Replay artifact generation to reconstruct execution timelines.

Safety notes:
- Avoid logging raw sensitive inputs; prefer decision metadata and counts.
- Denied/blocked actions are logged explicitly for incident review.
