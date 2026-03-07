"""Integration checks for evidence-pack and review documentation presence."""

from pathlib import Path


REQUIRED_DOCS = [
    "docs/evidence_pack/README.md",
    "docs/evidence_pack/architecture_summary.md",
    "docs/evidence_pack/control_summary.md",
    "docs/evidence_pack/policy_summary.md",
    "docs/evidence_pack/eval_summary.md",
    "docs/evidence_pack/telemetry_audit_summary.md",
    "docs/evidence_pack/launch_gate_summary.md",
    "docs/evidence_pack/residual_risks.md",
    "docs/evidence_pack/open_issues.md",
    "docs/operator/setup.md",
    "docs/reviewer/security_review_guide.md",
    "docs/portfolio/project_summary.md",
]


def test_required_evidence_and_review_docs_exist() -> None:
    missing = [path for path in REQUIRED_DOCS if not Path(path).is_file()]
    assert not missing, f"Missing required documentation files: {missing}"
