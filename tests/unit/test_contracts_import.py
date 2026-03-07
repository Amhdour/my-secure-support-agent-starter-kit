"""Baseline unit tests to ensure scaffold modules load."""


def test_app_contracts_importable() -> None:
    from app.contracts import Orchestrator  # noqa: F401
    from app.models import SupportAgentRequest, SupportAgentResponse  # noqa: F401


def test_retrieval_contracts_importable() -> None:
    from retrieval.contracts import RetrievalDocument, RetrievalQuery  # noqa: F401


def test_policy_contracts_importable() -> None:
    from policies.contracts import PolicyDecision  # noqa: F401


def test_orchestrator_module_importable() -> None:
    from app.orchestrator import SupportAgentOrchestrator  # noqa: F401


def test_tools_router_module_importable() -> None:
    from tools.router import SecureToolRouter  # noqa: F401


def test_policies_engine_importable() -> None:
    from policies.engine import RuntimePolicyEngine  # noqa: F401
    from policies.loader import load_policy  # noqa: F401


def test_telemetry_audit_modules_importable() -> None:
    from telemetry.audit.sinks import JsonlAuditSink  # noqa: F401
    from telemetry.audit.replay import build_replay_artifact  # noqa: F401


def test_evals_runner_importable() -> None:
    from evals.runner import SecurityEvalRunner  # noqa: F401


def test_launch_gate_importable() -> None:
    from launch_gate.engine import SecurityLaunchGate  # noqa: F401
