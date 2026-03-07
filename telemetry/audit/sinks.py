"""Audit sink implementations."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from telemetry.audit.contracts import AuditEvent, AuditSink


@dataclass
class JsonlAuditSink(AuditSink):
    """Writes structured audit events as JSONL for launch-gate/evidence ingestion."""

    output_path: Path

    def emit(self, event: AuditEvent) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(_event_to_record(event), sort_keys=True))
            handle.write("\n")


@dataclass
class InMemoryAuditSink(AuditSink):
    """In-memory sink useful for tests and local inspection."""

    events: list[AuditEvent] = field(default_factory=list)

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _event_to_record(event: AuditEvent) -> dict:
    return {
        "event_id": event.event_id,
        "trace_id": event.trace_id,
        "request_id": event.request_id,
        "actor_id": event.actor_id,
        "tenant_id": event.tenant_id,
        "event_type": event.event_type,
        "event_payload": dict(event.event_payload),
        "created_at": event.created_at,
    }
