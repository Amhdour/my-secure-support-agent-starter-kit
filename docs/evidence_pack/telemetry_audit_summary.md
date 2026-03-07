# Telemetry & Audit Summary

## Implemented
- Typed audit events for request lifecycle and decision points.
- Trace ID + request ID correlation across events.
- JSONL sink and in-memory sink.
- Replay artifact generation from ordered event timelines.

## Investigation Utility
- Includes allow/deny/fallback/error evidence by stage.
- Supports timeline reconstruction for post-incident review.

## Data Handling Notes
- Current implementation prefers decision metadata/counts over raw payload content.
- Sensitive fields should remain redacted/minimized in future integrations.
