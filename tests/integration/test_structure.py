"""Baseline integration checks for required directories."""

from pathlib import Path


REQUIRED_DIRS = [
    "app",
    "retrieval",
    "tools",
    "policies",
    "telemetry/audit",
    "evals",
    "launch_gate",
    "docs",
    "tests",
    "artifacts/logs",
    "config",
]


def test_required_directories_exist() -> None:
    for directory in REQUIRED_DIRS:
        assert Path(directory).is_dir(), f"Missing required directory: {directory}"
