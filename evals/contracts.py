"""Evaluation contracts and result models."""

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence


@dataclass(frozen=True)
class EvalScenarioResult:
    scenario_id: str
    title: str
    severity: str
    passed: bool
    details: str
    evidence: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class EvalResult:
    suite_name: str
    passed: bool
    summary: str
    scenario_results: Sequence[EvalScenarioResult] = field(default_factory=tuple)


class EvalSuite(Protocol):
    def run(self) -> EvalResult:
        """Run one evaluation suite and return summary result."""
        ...
