"""Tests for security eval runner and scenario execution."""

import json

from evals.contracts import BLOCKED_OUTCOME, EXPECTED_FAIL_OUTCOME, PASS_OUTCOME
from evals.runner import SecurityEvalRunner
from evals.scenario import load_scenarios


def test_scenario_file_loads_with_expected_baseline_entries() -> None:
    scenarios = load_scenarios("evals/scenarios/security_baseline.json")

    assert len(scenarios) == 11
    ids = {scenario.scenario_id for scenario in scenarios}
    assert "prompt_injection_direct" in ids
    assert "auditability_verification" in ids
    assert "indirect_injection_semantic_variant_expected_fail" in ids


def test_eval_runner_produces_regression_outputs(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-regression")

    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    assert len(result.scenario_results) == 11
    jsonl_files = list(tmp_path.glob("security-regression-*.jsonl"))
    summary_files = list(tmp_path.glob("security-regression-*.summary.json"))
    assert len(jsonl_files) == 1
    assert len(summary_files) == 1

    lines = jsonl_files[0].read_text().strip().splitlines()
    assert len(lines) == 11
    first_record = json.loads(lines[0])
    assert "scenario_id" in first_record
    assert "severity" in first_record
    assert "outcome" in first_record
    assert "result_type" in first_record

    summary = json.loads(summary_files[0].read_text())
    assert summary["total"] == 11
    assert "outcomes" in summary
    assert "pass" in summary["outcomes"]
    assert "fail" in summary["outcomes"]
    assert "expected_fail" in summary["outcomes"]
    assert "blocked" in summary["outcomes"]
    assert "inconclusive" in summary["outcomes"]


def test_security_scenarios_exercise_real_policy_retrieval_tool_paths(tmp_path) -> None:
    runner = SecurityEvalRunner(suite_name="security-runtime-paths")
    result = runner.run("evals/scenarios/security_baseline.json", output_dir=tmp_path)

    by_id = {item.scenario_id: item for item in result.scenario_results}
    assert by_id["cross_tenant_retrieval_attempt"].outcome == BLOCKED_OUTCOME
    assert by_id["forbidden_tool_argument_attempt"].outcome == BLOCKED_OUTCOME
    assert by_id["forbidden_tool_argument_attempt"].evidence["uses_mocked_path"] is True
    assert by_id["unauthorized_tool_use_attempt"].outcome == BLOCKED_OUTCOME
    assert by_id["fallback_to_rag_verification"].outcome == PASS_OUTCOME
    assert by_id["auditability_verification"].outcome == PASS_OUTCOME
    assert by_id["indirect_injection_semantic_variant_expected_fail"].outcome == EXPECTED_FAIL_OUTCOME
