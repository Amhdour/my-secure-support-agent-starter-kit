"""Launch gate contracts and readiness outputs."""

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence


GO_STATUS = "go"
CONDITIONAL_GO_STATUS = "conditional_go"
NO_GO_STATUS = "no_go"


@dataclass(frozen=True)
class GateCheckResult:
    check_name: str
    passed: bool
    details: str
    evidence: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ReadinessReport:
    status: str
    checks: Sequence[GateCheckResult]
    blockers: Sequence[str]
    residual_risks: Sequence[str]
    summary: str


class LaunchGate(Protocol):
    def evaluate(self) -> ReadinessReport:
        """Run launch readiness checks and return a structured report."""
        ...
