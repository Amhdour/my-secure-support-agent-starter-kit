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
    replay_artifact_glob: str = "artifacts/logs/replay*.json"
    min_eval_pass_rate: float = 0.9
    min_audit_events: int = 5
    required_audit_event_types: Sequence[str] = field(
        default_factory=lambda: (
            "request.start",
            "request.end",
            "policy.decision",
            "retrieval.decision",
            "tool.decision",
        )
    )
    require_fallback_ready: bool = True
    require_replay_artifact: bool = True


@dataclass
class SecurityLaunchGate:
    repo_root: Path
    config: LaunchGateConfig = field(default_factory=LaunchGateConfig)

    def evaluate(self) -> ReadinessReport:
        checks = [
            self._check_mandatory_controls(),
            self._check_policy_artifact(),
            self._check_retrieval_boundary_config(),
            self._check_tool_router_enforcement_config(),
            self._check_kill_switch_state(),
            self._check_audit_minimums(),
            self._check_replay_artifact(),
            self._check_eval_threshold(),
            self._check_fallback_readiness(),
        ]

        blocker_checks = {
            "mandatory_controls",
            "policy_artifact",
            "retrieval_boundary_config",
            "tool_router_enforcement_config",
            "kill_switch_state",
            "eval_threshold",
        }
        residual_checks = {"audit_minimums", "replay_artifact", "fallback_readiness"}

        blockers = [check.details for check in checks if not check.passed and check.check_name in blocker_checks]
        residual_risks = [check.details for check in checks if not check.passed and check.check_name in residual_checks]

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
            evidence={
                "policy_path": str(policy_path),
                "policy_exists": policy_path.is_file(),
                "policy_valid": runtime_policy.valid,
                "validation_errors": list(runtime_policy.validation_errors),
            },
        )

    def _check_retrieval_boundary_config(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        if not runtime_policy.valid:
            return GateCheckResult(
                check_name="retrieval_boundary_config",
                passed=False,
                details="retrieval boundary config invalid: policy artifact invalid",
                evidence={"policy_path": str(policy_path), "policy_valid": runtime_policy.valid},
            )

        allowed_tenants = runtime_policy.retrieval.allowed_tenants
        tenant_sources = runtime_policy.retrieval.tenant_allowed_sources
        trust_domains = tuple(runtime_policy.retrieval.allowed_trust_domains)

        tenants_missing_allowlists = [tenant for tenant in allowed_tenants if len(tenant_sources.get(tenant, tuple())) == 0]
        unexpected_tenant_mappings = [tenant for tenant in tenant_sources.keys() if tenant not in set(allowed_tenants)]

        passed = (
            len(allowed_tenants) > 0
            and len(tenants_missing_allowlists) == 0
            and len(unexpected_tenant_mappings) == 0
            and runtime_policy.retrieval.require_trust_metadata
            and runtime_policy.retrieval.require_provenance
            and len(trust_domains) > 0
        )
        details = (
            "retrieval boundary config satisfied"
            if passed
            else "retrieval boundary config missing tenant/source/trust/provenance enforcement"
        )
        return GateCheckResult(
            check_name="retrieval_boundary_config",
            passed=passed,
            details=details,
            evidence={
                "allowed_tenants": list(allowed_tenants),
                "tenant_allowed_sources": {tenant: list(sources) for tenant, sources in tenant_sources.items()},
                "tenants_missing_source_allowlists": tenants_missing_allowlists,
                "unexpected_tenant_source_mappings": unexpected_tenant_mappings,
                "require_trust_metadata": runtime_policy.retrieval.require_trust_metadata,
                "require_provenance": runtime_policy.retrieval.require_provenance,
                "allowed_trust_domains": list(trust_domains),
            },
        )

    def _check_tool_router_enforcement_config(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        if not runtime_policy.valid:
            return GateCheckResult(
                check_name="tool_router_enforcement_config",
                passed=False,
                details="tool-router enforcement config invalid: policy artifact invalid",
                evidence={"policy_path": str(policy_path), "policy_valid": runtime_policy.valid},
            )

        allowed_tools = runtime_policy.tools.allowed_tools
        rate_limits = runtime_policy.tools.rate_limits_per_tool
        forbidden_fields = runtime_policy.tools.forbidden_fields_per_tool

        passed = len(allowed_tools) > 0 and len(rate_limits) > 0 and len(forbidden_fields) > 0
        details = (
            "tool-router enforcement config satisfied"
            if passed
            else "tool-router enforcement config missing allowlist/rate-limit/forbidden-field controls"
        )
        return GateCheckResult(
            check_name="tool_router_enforcement_config",
            passed=passed,
            details=details,
            evidence={
                "allowed_tools": list(allowed_tools),
                "rate_limits_per_tool": dict(rate_limits),
                "forbidden_fields_per_tool": {tool: list(fields) for tool, fields in forbidden_fields.items()},
                "forbidden_tools": list(runtime_policy.tools.forbidden_tools),
                "confirmation_required_tools": list(runtime_policy.tools.confirmation_required_tools),
            },
        )

    def _check_kill_switch_state(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        passed = runtime_policy.valid and (not runtime_policy.kill_switch)
        details = "kill switch disabled for production" if passed else "kill switch enabled or policy invalid for production"
        return GateCheckResult(
            check_name="kill_switch_state",
            passed=passed,
            details=details,
            evidence={
                "policy_path": str(policy_path),
                "policy_valid": runtime_policy.valid,
                "kill_switch": runtime_policy.kill_switch,
            },
        )

    def _check_audit_minimums(self) -> GateCheckResult:
        audit_path = self.repo_root / self.config.audit_log_path
        if not audit_path.is_file():
            return GateCheckResult(
                check_name="audit_minimums",
                passed=False,
                details="audit evidence missing",
                evidence={"audit_path": str(audit_path), "audit_exists": False},
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
                "audit_path": str(audit_path),
                "audit_exists": True,
                "event_count": len(records),
                "required_min": self.config.min_audit_events,
                "missing_event_types": missing_types,
            },
        )

    def _check_replay_artifact(self) -> GateCheckResult:
        replay_files = sorted(self.repo_root.glob(self.config.replay_artifact_glob))
        if not self.config.require_replay_artifact:
            return GateCheckResult(
                check_name="replay_artifact",
                passed=True,
                details="replay artifact check not required",
                evidence={"glob": self.config.replay_artifact_glob, "matched_files": [str(p) for p in replay_files]},
            )

        if not replay_files:
            return GateCheckResult(
                check_name="replay_artifact",
                passed=False,
                details="replay artifact missing",
                evidence={"glob": self.config.replay_artifact_glob, "matched_files": []},
            )

        latest = replay_files[-1]
        try:
            replay = json.loads(latest.read_text())
        except (OSError, json.JSONDecodeError):
            return GateCheckResult(
                check_name="replay_artifact",
                passed=False,
                details="replay artifact unreadable",
                evidence={"replay_path": str(latest)},
            )

        has_timeline = isinstance(replay, dict) and isinstance(replay.get("timeline"), list) and len(replay.get("timeline", [])) > 0
        passed = bool(has_timeline)
        details = "replay artifact satisfied" if passed else "replay artifact missing timeline evidence"
        return GateCheckResult(
            check_name="replay_artifact",
            passed=passed,
            details=details,
            evidence={
                "replay_path": str(latest),
                "has_timeline": has_timeline,
                "timeline_length": len(replay.get("timeline", [])) if isinstance(replay, dict) else 0,
            },
        )

    def _check_eval_threshold(self) -> GateCheckResult:
        summary_files = sorted(self.repo_root.glob(self.config.eval_summary_glob))
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

        outcomes = summary.get("outcomes", {})
        fail_count = int(outcomes.get("fail", 0)) if isinstance(outcomes, dict) else 0
        inconclusive_count = int(outcomes.get("inconclusive", 0)) if isinstance(outcomes, dict) else 0

        passed = pass_rate >= self.config.min_eval_pass_rate and total > 0 and fail_count == 0 and inconclusive_count == 0
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
                "outcomes": outcomes if isinstance(outcomes, dict) else {},
                "fail_count": fail_count,
                "inconclusive_count": inconclusive_count,
            },
        )

    def _check_fallback_readiness(self) -> GateCheckResult:
        policy_path = self.repo_root / self.config.policy_path
        runtime_policy = load_policy(policy_path, environment="production")

        if not runtime_policy.valid:
            return GateCheckResult(
                check_name="fallback_readiness",
                passed=False,
                details="fallback readiness not satisfied: policy invalid",
                evidence={
                    "policy_path": str(policy_path),
                    "policy_valid": runtime_policy.valid,
                },
            )

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
