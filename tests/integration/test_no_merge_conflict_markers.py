"""Integration check to ensure no unresolved merge markers are committed."""

from pathlib import Path


MARKERS = ("<<<<<<< ", "=======", ">>>>>>> ")


def test_no_unresolved_merge_conflict_markers() -> None:
    tracked = [
        path
        for path in Path(".").rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
    ]

    offenders: list[str] = []
    for path in tracked:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            if line.startswith(MARKERS):
                offenders.append(f"{path}:{idx}")

    assert not offenders, f"Unresolved merge markers found: {offenders}"
