"""Replay artifact generation from audit event streams."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from telemetry.audit.contracts import AuditEvent


@dataclass(frozen=True)
class ReplayArtifact:
    """Replay-friendly execution artifact."""

    trace_id: str
    request_id: str
    actor_id: str
    tenant_id: str
    timeline: tuple[dict, ...]


def build_replay_artifact(events: Sequence[AuditEvent]) -> ReplayArtifact:
    if not events:
        raise ValueError("cannot build replay artifact from empty event list")

    ordered = tuple(sorted(events, key=lambda item: item.created_at))
    first = ordered[0]

    timeline = tuple(
        {
            "event_type": event.event_type,
            "created_at": event.created_at,
            "payload": dict(event.event_payload),
        }
        for event in ordered
    )

    return ReplayArtifact(
        trace_id=first.trace_id,
        request_id=first.request_id,
        actor_id=first.actor_id,
        tenant_id=first.tenant_id,
        timeline=timeline,
    )


def write_replay_artifact(artifact: ReplayArtifact, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "trace_id": artifact.trace_id,
                "request_id": artifact.request_id,
                "actor_id": artifact.actor_id,
                "tenant_id": artifact.tenant_id,
                "timeline": list(artifact.timeline),
            },
            sort_keys=True,
            indent=2,
        )
    )
