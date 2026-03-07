"""Tests for launch-gate readiness logic and blocker classification."""

import json
from pathlib import Path

from launch_gate import CONDITIONAL_GO_STATUS, GO_STATUS, NO_GO_STATUS
from launch_gate.engine import LaunchGateConfig, SecurityLaunchGate


def _setup_repo_like_layout(base: Path) -> None:
    (base / "app").mkdir(parents=True, exist_ok=True)
    (base / "policies").mkdir(parents=True, exist_ok=True)
    (base / "retrieval").mkdir(parents=True, exist_ok=True)
    (base / "tools").mkdir(parents=True, exist_ok=True)
    (base / "telemetry/audit").mkdir(parents=True, exist_ok=True)
    (base / "artifacts/logs/evals").mkdir(parents=True, exist_ok=True)
    (base / "artifacts/logs").mkdir(parents=True, exist_ok=True)

    (base / "app/orchestrator.py").write_text("# control")
    (base / "policies/engine.py").write_text("# control")
    (base / "retrieval/service.py").write_text("# control")
    (base / "tools/router.py").write_text("# control")
    (base / "telemetry/audit/contracts.py").write_text("# control")

    (base / "policies/bundles/default").mkdir(parents=True, exist_ok=True)
    (base / "policies/bundles/default/policy.json").write_text(
        json.dumps(
            {
                "global": {"kill_switch": False, "fallback_to_rag": True, "default_risk_tier": "high"},
                "risk_tiers": {"high": {"max_retrieval_top_k": 1, "tools_enabled": False}},
                "retrieval": {
                    "allowed_tenants": ["tenant-a"],
                    "tenant_allowed_sources": {"tenant-a": ["kb-main"]},
                    "require_trust_metadata": True,
                    "require_provenance": True,
                    "allowed_trust_domains": ["internal"],
                },
                "tools": {
                    "allowed_tools": ["ticket_lookup"],
                    "forbidden_tools": ["admin_shell"],
                    "confirmation_required_tools": [],
                    "forbidden_fields_per_tool": {"ticket_lookup": ["ssn"]},
                    "rate_limits_per_tool": {"ticket_lookup": 1},
                },
            }
        )
    )

    (base / "artifacts/logs/audit.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"event_type": "request.start"}),
                json.dumps({"event_type": "policy.decision"}),
                json.dumps({"event_type": "retrieval.decision"}),
                json.dumps({"event_type": "tool.decision"}),
                json.dumps({"event_type": "request.end"}),
            ]
        )
    )

    (base / "artifacts/logs/replay.json").write_text(
        json.dumps({"trace_id": "trace-1", "request_id": "req-1", "timeline": [{"event_type": "request.start"}]})
    )

    (base / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps(
            {
                "total": 10,
                "passed_count": 9,
                "outcomes": {
                    "pass": 9,
                    "fail": 0,
                    "expected_fail": 0,
                    "blocked": 1,
                    "inconclusive": 0,
                },
            }
        )
    )


def test_missing_mandatory_controls_yields_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "tools/router.py").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("missing mandatory controls" in blocker for blocker in report.blockers)


def test_missing_policy_artifact_is_blocking(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "policies/bundles/default/policy.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("missing or invalid policy artifact" in blocker for blocker in report.blockers)


def test_missing_telemetry_evidence_is_residual_risk(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/audit.jsonl").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert any("audit evidence missing" in risk for risk in report.residual_risks)


def test_missing_eval_summary_is_blocking(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("eval summary evidence missing" in blocker for blocker in report.blockers)


def test_eval_threshold_failure_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps(
            {
                "total": 10,
                "passed_count": 6,
                "outcomes": {"pass": 6, "fail": 4, "expected_fail": 0, "blocked": 0, "inconclusive": 0},
            }
        )
    )

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("eval threshold failed" in blocker for blocker in report.blockers)


def test_missing_fallback_readiness_is_residual_risk(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload["global"]["fallback_to_rag"] = False
    policy_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert any("fallback readiness not satisfied" in risk for risk in report.residual_risks)


def test_readiness_output_generation_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == GO_STATUS
    assert report.blockers == ()
    assert report.residual_risks == ()
    assert "status=go" in report.summary


def test_blocker_detection_and_conditional_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    # keep blockers clear, but remove replay evidence to introduce residual risk
    (tmp_path / "artifacts/logs/replay.json").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert report.blockers == ()
    assert any("replay artifact missing" in risk for risk in report.residual_risks)


def test_blocker_detection_list_contains_all_critical_failures(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "app/orchestrator.py").unlink()
    (tmp_path / "policies/bundles/default/policy.json").write_text("{ invalid")

    gate = SecurityLaunchGate(repo_root=tmp_path, config=LaunchGateConfig())
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert len(report.blockers) >= 2


def test_unreadable_eval_summary_is_blocking(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text("{not-json")

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("eval summary unreadable" in blocker for blocker in report.blockers)


def test_production_kill_switch_enabled_is_blocking(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload["global"]["kill_switch"] = True
    policy_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("kill switch enabled" in blocker for blocker in report.blockers)


def test_invalid_policy_marks_fallback_readiness_as_failed(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "policies/bundles/default/policy.json").write_text("{ invalid")

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    fallback_check = next(check for check in report.checks if check.check_name == "fallback_readiness")
    assert fallback_check.passed is False
    assert "policy invalid" in fallback_check.details


def test_retrieval_boundary_blocks_when_allowed_tenant_has_no_source_allowlist(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload["retrieval"]["allowed_tenants"] = ["tenant-a", "tenant-b"]
    payload["retrieval"]["tenant_allowed_sources"] = {"tenant-a": ["kb-main"]}
    policy_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("retrieval boundary config" in blocker for blocker in report.blockers)


def test_retrieval_boundary_blocks_when_tenant_source_mapping_not_allowlisted(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    policy_path = tmp_path / "policies/bundles/default/policy.json"
    payload = json.loads(policy_path.read_text())
    payload["retrieval"]["allowed_tenants"] = ["tenant-a"]
    payload["retrieval"]["tenant_allowed_sources"] = {"tenant-a": ["kb-main"], "tenant-x": ["kb-x"]}
    policy_path.write_text(json.dumps(payload))

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("retrieval boundary config" in blocker for blocker in report.blockers)
