"""Reusable security eval and red-team harness."""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from evals.contracts import (
    BLOCKED_OUTCOME,
    EXPECTED_FAIL_OUTCOME,
    FAIL_OUTCOME,
    INCONCLUSIVE_OUTCOME,
    PASS_OUTCOME,
    EvalResult,
    EvalScenarioResult,
)
from evals.runtime import build_runtime_fixture, make_invocation, make_request
from evals.scenario import SecurityScenario, load_scenarios


@dataclass
class SecurityEvalRunner:
    suite_name: str = "security-redteam"

    def run(self, scenario_file: str | Path, *, output_dir: str | Path = "artifacts/logs/evals") -> EvalResult:
        scenarios = load_scenarios(scenario_file)
        scenario_results = tuple(self._run_scenario(scenario) for scenario in scenarios)

        outcome_counts = {
            PASS_OUTCOME: sum(1 for item in scenario_results if item.outcome == PASS_OUTCOME),
            FAIL_OUTCOME: sum(1 for item in scenario_results if item.outcome == FAIL_OUTCOME),
            EXPECTED_FAIL_OUTCOME: sum(1 for item in scenario_results if item.outcome == EXPECTED_FAIL_OUTCOME),
            BLOCKED_OUTCOME: sum(1 for item in scenario_results if item.outcome == BLOCKED_OUTCOME),
            INCONCLUSIVE_OUTCOME: sum(1 for item in scenario_results if item.outcome == INCONCLUSIVE_OUTCOME),
        }
        passed = outcome_counts[FAIL_OUTCOME] == 0 and outcome_counts[INCONCLUSIVE_OUTCOME] == 0
        summary = (
            f"pass={outcome_counts[PASS_OUTCOME]}; fail={outcome_counts[FAIL_OUTCOME]}; "
            f"expected_fail={outcome_counts[EXPECTED_FAIL_OUTCOME]}; blocked={outcome_counts[BLOCKED_OUTCOME]}; "
            f"inconclusive={outcome_counts[INCONCLUSIVE_OUTCOME]}"
        )

        eval_result = EvalResult(
            suite_name=self.suite_name,
            passed=passed,
            summary=summary,
            scenario_results=scenario_results,
        )

        self._write_outputs(eval_result, output_dir=Path(output_dir), outcome_counts=outcome_counts)
        return eval_result

    def _run_scenario(self, scenario: SecurityScenario) -> EvalScenarioResult:
        evidence: dict[str, object] = {
            "operation": scenario.operation,
            "label": scenario.label,
            "execution_path": scenario.execution_path,
            "limitation_reason": scenario.limitation_reason,
        }

        try:
            fixture = build_runtime_fixture(scenario.policy_overrides)

            if scenario.operation == "orchestrator_request":
                request = make_request(
                    request_id=scenario.request.get("request_id", scenario.scenario_id),
                    tenant_id=scenario.request.get("tenant_id", "tenant-a"),
                    user_text=scenario.request.get("user_text", "help"),
                )
                response = fixture.orchestrator.run(request)
                event_types = [event.event_type for event in fixture.audit_sink.events]
                evidence.update(
                    {
                        "status": response.status,
                        "answer_text": response.answer_text,
                        "tool_decision_statuses": [decision.status for decision in response.tool_decisions],
                        "event_types": event_types,
                        "retrieved_document_ids": list(response.trace.retrieved_document_ids),
                    }
                )

            elif scenario.operation == "tool_invocation":
                invocation = make_invocation(
                    request_id=scenario.invocation.get("request_id", scenario.scenario_id),
                    tenant_id=scenario.invocation.get("tenant_id", "tenant-a"),
                    tool_name=scenario.invocation.get("tool_name", "ticket_lookup"),
                    action=scenario.invocation.get("action", "lookup"),
                    arguments=scenario.invocation.get("arguments", {}),
                    confirmed=bool(scenario.invocation.get("confirmed", False)),
                )
                decision = fixture.tool_router.route(invocation)
                evidence.update({"tool_decision_status": decision.status, "tool_decision_reason": decision.reason})

            elif scenario.operation == "audit_verification":
                request = make_request(
                    request_id=scenario.request.get("request_id", scenario.scenario_id),
                    tenant_id=scenario.request.get("tenant_id", "tenant-a"),
                    user_text=scenario.request.get("user_text", "help"),
                )
                _ = fixture.orchestrator.run(request)
                event_types = [event.event_type for event in fixture.audit_sink.events]
                evidence.update({"event_types": event_types, "event_count": len(event_types)})

            checks_passed, details = _evaluate_expectations(dict(scenario.expectations), evidence)
            outcome = _classify_outcome(
                checks_passed=checks_passed,
                expectations=dict(scenario.expectations),
                evidence=evidence,
            )
            passed = outcome in {PASS_OUTCOME, BLOCKED_OUTCOME}
            return EvalScenarioResult(
                scenario_id=scenario.scenario_id,
                title=scenario.title,
                severity=scenario.severity,
                passed=passed,
                outcome=outcome,
                details=details,
                evidence=evidence,
            )
        except Exception as exc:
            evidence["error"] = {"type": type(exc).__name__, "message": str(exc)}
            return EvalScenarioResult(
                scenario_id=scenario.scenario_id,
                title=scenario.title,
                severity=scenario.severity,
                passed=False,
                outcome=INCONCLUSIVE_OUTCOME,
                details="scenario execution error",
                evidence=evidence,
            )

    def _write_outputs(self, result: EvalResult, *, output_dir: Path, outcome_counts: dict[str, int]) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        jsonl_path = output_dir / f"{self.suite_name}-{stamp}.jsonl"
        summary_path = output_dir / f"{self.suite_name}-{stamp}.summary.json"

        with jsonl_path.open("w", encoding="utf-8") as handle:
            for scenario_result in result.scenario_results:
                handle.write(
                    json.dumps(
                        {
                            "scenario_id": scenario_result.scenario_id,
                            "title": scenario_result.title,
                            "severity": scenario_result.severity,
                            "passed": scenario_result.passed,
                            "outcome": scenario_result.outcome,
                            "details": scenario_result.details,
                            "evidence": scenario_result.evidence,
                        },
                        sort_keys=True,
                    )
                )
                handle.write("\n")

        summary_path.write_text(
            json.dumps(
                {
                    "suite_name": result.suite_name,
                    "passed": result.passed,
                    "summary": result.summary,
                    "total": len(result.scenario_results),
                    "passed_count": sum(1 for item in result.scenario_results if item.passed),
                    "outcomes": outcome_counts,
                },
                sort_keys=True,
                indent=2,
            )
        )


def _classify_outcome(*, checks_passed: bool, expectations: dict, evidence: dict) -> str:
    if checks_passed:
        if evidence.get("status") == "blocked":
            return BLOCKED_OUTCOME
        return PASS_OUTCOME

    if bool(expectations.get("expected_fail", False)):
        return EXPECTED_FAIL_OUTCOME
    return FAIL_OUTCOME


def _evaluate_expectations(expectations: dict, evidence: dict) -> tuple[bool, str]:
    checks: list[tuple[bool, str]] = []

    if "status" in expectations:
        checks.append((evidence.get("status") == expectations["status"], f"expected status {expectations['status']}"))

    if "tool_decision_status" in expectations:
        checks.append(
            (
                evidence.get("tool_decision_status") == expectations["tool_decision_status"],
                f"expected tool decision {expectations['tool_decision_status']}",
            )
        )

    if "answer_contains" in expectations:
        expected = str(expectations["answer_contains"])
        checks.append((expected in str(evidence.get("answer_text", "")), f"answer missing required text: {expected}"))

    if "answer_not_contains" in expectations:
        expected = str(expectations["answer_not_contains"])
        checks.append((expected not in str(evidence.get("answer_text", "")), f"answer contains forbidden text: {expected}"))

    required_events = expectations.get("required_events", [])
    if isinstance(required_events, list):
        event_types = evidence.get("event_types", [])
        for event in required_events:
            checks.append((event in event_types, f"required event missing: {event}"))

    forbidden_events = expectations.get("forbidden_events", [])
    if isinstance(forbidden_events, list):
        event_types = evidence.get("event_types", [])
        for event in forbidden_events:
            checks.append((event not in event_types, f"forbidden event present: {event}"))

    min_event_count = expectations.get("min_event_count")
    if isinstance(min_event_count, int):
        checks.append((len(evidence.get("event_types", [])) >= min_event_count, f"expected at least {min_event_count} events"))

    min_retrieved_docs = expectations.get("min_retrieved_docs")
    if isinstance(min_retrieved_docs, int):
        checks.append(
            (
                len(evidence.get("retrieved_document_ids", [])) >= min_retrieved_docs,
                f"expected at least {min_retrieved_docs} retrieved docs",
            )
        )

    max_retrieved_docs = expectations.get("max_retrieved_docs")
    if isinstance(max_retrieved_docs, int):
        checks.append(
            (
                len(evidence.get("retrieved_document_ids", [])) <= max_retrieved_docs,
                f"expected at most {max_retrieved_docs} retrieved docs",
            )
        )

    if not checks:
        return False, "no expectations defined"

    failed = [msg for ok, msg in checks if not ok]
    if failed:
        return False, "; ".join(failed)
    return True, "all expectations satisfied"


if __name__ == "__main__":
    runner = SecurityEvalRunner()
    result = runner.run("evals/scenarios/security_baseline.json")
    print(result.summary)
