"""Integration checks for router-only tool execution paths."""

from pathlib import Path


ALLOWED_REGISTRY_EXECUTE_CALL_SITES = {
    "tools/router.py",
}


def test_registry_execute_called_only_by_router_in_runtime_code() -> None:
    offenders: list[str] = []
    for path in Path('.').rglob('*.py'):
        rel = path.as_posix()
        if rel.startswith('.git/') or '/tests/' in f'/{rel}' or rel.startswith('tests/'):
            continue
        text = path.read_text(encoding='utf-8')
        if 'registry.execute(' in text and rel not in ALLOWED_REGISTRY_EXECUTE_CALL_SITES:
            offenders.append(rel)

    assert not offenders, f"Tool registry execution bypass risk: unexpected call sites {offenders}"
