"""App-level contracts and orchestration protocol."""

from typing import Protocol

from app.models import SupportAgentRequest, SupportAgentResponse


class Orchestrator(Protocol):
    """High-level orchestration contract for support-agent request handling."""

    def run(self, request: SupportAgentRequest) -> SupportAgentResponse:
        """Run one request through the orchestrated pipeline."""
        ...
