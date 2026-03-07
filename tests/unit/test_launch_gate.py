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
                "retrieval": {"allowed_tenants": ["tenant-a"], "tenant_allowed_sources": {"tenant-a": ["kb-main"]}},
                "tools": {
                    "allowed_tools": ["ticket_lookup"],
                    "forbidden_tools": ["admin_shell"],
                    "confirmation_required_tools": [],
                    "forbidden_fields_per_tool": {},
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

    (base / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps({"total": 10, "passed_count": 10})
    )


def test_missing_mandatory_controls_yields_no_go(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "tools/router.py").unlink()

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("missing mandatory controls" in blocker for blocker in report.blockers)


def test_eval_threshold_failure_blocks_readiness(tmp_path) -> None:
    _setup_repo_like_layout(tmp_path)
    (tmp_path / "artifacts/logs/evals/security-redteam-20260101T000000Z.summary.json").write_text(
        json.dumps({"total": 10, "passed_count": 6})
    )

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == NO_GO_STATUS
    assert any("eval threshold failed" in blocker for blocker in report.blockers)


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
    # keep blockers clear, but remove enough audit evidence to introduce residual risk
    (tmp_path / "artifacts/logs/audit.jsonl").write_text(json.dumps({"event_type": "request.start"}) + "\n")

    gate = SecurityLaunchGate(repo_root=tmp_path)
    report = gate.evaluate()

    assert report.status == CONDITIONAL_GO_STATUS
    assert report.blockers == ()
    assert any("audit minimums not satisfied" in risk for risk in report.residual_risks)


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
