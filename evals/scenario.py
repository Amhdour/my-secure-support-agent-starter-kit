"""Scenario format and loader for security eval harness."""

from dataclasses import dataclass, field
import json
from pathlib import Path
<<<<<<< HEAD
from typing import Any, Mapping, Sequence
=======
from typing import Any, Mapping
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)


@dataclass(frozen=True)
class SecurityScenario:
    scenario_id: str
    title: str
    severity: str
    operation: str
    request: Mapping[str, Any] = field(default_factory=dict)
    invocation: Mapping[str, Any] = field(default_factory=dict)
    policy_overrides: Mapping[str, Any] = field(default_factory=dict)
    expectations: Mapping[str, Any] = field(default_factory=dict)
    label: str = "runtime"
<<<<<<< HEAD
=======
    execution_path: str = "full_runtime"
    limitation_reason: str = ""
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)


VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_OPERATIONS = {"orchestrator_request", "tool_invocation", "audit_verification"}
<<<<<<< HEAD
=======
VALID_EXECUTION_PATHS = {"full_runtime", "router_only"}
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)


def load_scenarios(path: str | Path) -> tuple[SecurityScenario, ...]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, dict) or not isinstance(payload.get("scenarios"), list):
        raise ValueError("scenario file must contain a 'scenarios' list")

    scenarios: list[SecurityScenario] = []
    for item in payload["scenarios"]:
        if not isinstance(item, dict):
            raise ValueError("scenario entries must be objects")
        scenario = SecurityScenario(
            scenario_id=str(item.get("id", "")),
            title=str(item.get("title", "")),
            severity=str(item.get("severity", "")).lower(),
            operation=str(item.get("operation", "")),
            request=item.get("request", {}) if isinstance(item.get("request", {}), dict) else {},
            invocation=item.get("invocation", {}) if isinstance(item.get("invocation", {}), dict) else {},
            policy_overrides=item.get("policy_overrides", {}) if isinstance(item.get("policy_overrides", {}), dict) else {},
            expectations=item.get("expectations", {}) if isinstance(item.get("expectations", {}), dict) else {},
            label=str(item.get("label", "runtime")),
<<<<<<< HEAD
=======
            execution_path=str(item.get("execution_path", "full_runtime")),
            limitation_reason=str(item.get("limitation_reason", "")),
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
        )
        _validate_scenario(scenario)
        scenarios.append(scenario)
    return tuple(scenarios)


def _validate_scenario(scenario: SecurityScenario) -> None:
    if not scenario.scenario_id:
        raise ValueError("scenario id is required")
    if scenario.severity not in VALID_SEVERITIES:
        raise ValueError(f"invalid severity for {scenario.scenario_id}: {scenario.severity}")
    if scenario.operation not in VALID_OPERATIONS:
        raise ValueError(f"invalid operation for {scenario.scenario_id}: {scenario.operation}")
<<<<<<< HEAD
=======
    if scenario.execution_path not in VALID_EXECUTION_PATHS:
        raise ValueError(f"invalid execution_path for {scenario.scenario_id}: {scenario.execution_path}")
    if scenario.execution_path == "router_only" and not scenario.limitation_reason:
        raise ValueError(f"router_only scenario must provide limitation_reason: {scenario.scenario_id}")
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
