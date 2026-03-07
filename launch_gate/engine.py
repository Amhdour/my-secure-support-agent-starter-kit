"""Machine-checkable launch-gate readiness evaluator."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from launch_gate.contracts import (
    CONDITIONAL_GO_STATUS,
    GO_STATUS,
    NO_GO_STATUS,
    GateCheckResult,
    ReadinessReport,
)
from policies.loader import load_policy


@dataclass
class LaunchGateConfig:
    mandatory_control_files: Sequence[str] = field(
        default_factory=lambda: (
            "app/orchestrator.py",
            "policies/engine.py",
            "retrieval/service.py",
            "tools/router.py",
            "telemetry/audit/contracts.py",
        )
    )
    policy_path: str = "policies/bundles/default/policy.json"
    audit_log_path: str = "artifacts/logs/audit.jsonl"
    eval_summary_glob: str = "artifacts/logs/evals/*.summary.json"
    min_eval_pass_rate: float = 0.9
    min_audit_events: int = 5
    required_audit_event_types: Sequence[str] = field(
        default_factory=lambda: (
            "request.start",
            "request.end",
            "policy.decision",
        )
    )
    require_fallback_ready: bool = True


@dataclass
class SecurityLaunchGate:
    repo_root: Path
    config: LaunchGateConfig = field(default_factory=LaunchGateConfig)

    def evaluate(self) -> ReadinessReport:
        checks = [
            self._check_mandatory_controls(),
            self._check_policy_artifact(),
            self._check_audit_minimums(),
            self._check_eval_threshold(),
            self._check_fallback_readiness(),
        ]

        blockers = [check.details for check in checks if not check.passed and check.check_name in {"mandatory_controls", "policy_artifact", "eval_threshold"}]
        residual_risks = [check.details for check in checks if not check.passed and check.check_name in {"audit_minimums", "fallback_readiness"}]

        if blockers:
            status = NO_GO_STATUS
        elif residual_risks:
            status = CONDITIONAL_GO_STATUS
        else:
            status = GO_STATUS

        summary = (
            f"status={status}; passed={sum(1 for c in checks if c.passed)}/{len(checks)}; "
            f"blockers={len(blockers)}; residual_risks={len(residual_risks)}"
        )
        return ReadinessReport(
            status=status,
            checks=tuple(checks),
            blockers=tuple(blockers),
            residual_risks=tuple(residual_risks),
            summary=summary,
        )

    def _check_mandatory_controls(self) -> GateCheckResult:
        missing = [path for path in self.config.mandatory_control_files if not (self.repo_root / path).is_file()]
        passed = len(missing) == 0
        details = "all mandatory controls present" if passed else f"missing mandatory controls: {', '.join(missing)}"
        return GateCheckResult(
            check_name="mandatory_controls",
            passed=passed,
            details=details,
            evidence={"required": list(self.config.mandatory_control_files), "missing": missing},
        )

    def _check_policy_artifact(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")
        passed = policy_path.is_file() and runtime_policy.valid
        details = "policy artifact valid" if passed else "missing or invalid policy artifact"
        return GateCheckResult(
            check_name="policy_artifact",
            passed=passed,
            details=details,
            evidence={"policy_path": str(policy_path), "policy_valid": runtime_policy.valid},
        )

    def _check_audit_minimums(self) -> GateCheckResult:
        audit_path = self.repo_root / self.config.audit_log_path
        if not audit_path.is_file():
            return GateCheckResult(
                check_name="audit_minimums",
                passed=False,
                details="audit evidence missing",
                evidence={"audit_path": str(audit_path)},
            )

        records = _read_jsonl(audit_path)
        event_types = [record.get("event_type") for record in records if isinstance(record, dict)]
        missing_types = [item for item in self.config.required_audit_event_types if item not in event_types]

        passed = len(records) >= self.config.min_audit_events and not missing_types
        details = "audit minimums satisfied" if passed else "audit minimums not satisfied"
        return GateCheckResult(
            check_name="audit_minimums",
            passed=passed,
            details=details,
            evidence={
                "event_count": len(records),
                "required_min": self.config.min_audit_events,
                "missing_event_types": missing_types,
                "audit_path": str(audit_path),
            },
        )

    def _check_eval_threshold(self) -> GateCheckResult:
        summary_files = sorted((self.repo_root).glob(self.config.eval_summary_glob))
        if not summary_files:
            return GateCheckResult(
                check_name="eval_threshold",
                passed=False,
                details="eval summary evidence missing",
                evidence={"glob": self.config.eval_summary_glob},
            )

        latest = summary_files[-1]
        try:
            summary = json.loads(latest.read_text())
        except (OSError, json.JSONDecodeError):
            return GateCheckResult(
                check_name="eval_threshold",
                passed=False,
                details="eval summary unreadable",
                evidence={"summary_path": str(latest)},
            )

        total = int(summary.get("total", 0))
        passed_count = int(summary.get("passed_count", 0))
        pass_rate = (passed_count / total) if total else 0.0

        passed = pass_rate >= self.config.min_eval_pass_rate and total > 0
        details = "eval threshold satisfied" if passed else "eval threshold failed"
        return GateCheckResult(
            check_name="eval_threshold",
            passed=passed,
            details=details,
            evidence={
                "summary_path": str(latest),
                "total": total,
                "passed_count": passed_count,
                "pass_rate": pass_rate,
                "required_pass_rate": self.config.min_eval_pass_rate,
            },
        )

    def _check_fallback_readiness(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        fallback_enabled = bool(runtime_policy.fallback_to_rag)
        high_risk = runtime_policy.risk_tiers.get("high")
        high_risk_tools_disabled = bool(high_risk and not high_risk.tools_enabled)

        passed = (not self.config.require_fallback_ready) or (fallback_enabled and high_risk_tools_disabled)
        details = "fallback readiness satisfied" if passed else "fallback readiness not satisfied"
        return GateCheckResult(
            check_name="fallback_readiness",
            passed=passed,
            details=details,
            evidence={
                "fallback_enabled": fallback_enabled,
                "high_risk_tools_disabled": high_risk_tools_disabled,
                "require_fallback_ready": self.config.require_fallback_ready,
            },
        )


def _read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    try:
        raw = path.read_text()
    except OSError:
        return records
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


if __name__ == "__main__":
    report = SecurityLaunchGate(repo_root=Path(".")).evaluate()
    print(report.summary)
