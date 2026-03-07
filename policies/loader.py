"""Policy loader with environment-specific overrides and safe-fail behavior."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping

from policies.schema import RuntimePolicy, build_runtime_policy, restrictive_policy


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_policy(path: str | Path, *, environment: str) -> RuntimePolicy:
    file_path = Path(path)
    if not file_path.is_file():
        return restrictive_policy(environment=environment, reason="policy file missing")

    try:
        payload = json.loads(file_path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return restrictive_policy(environment=environment, reason="policy file unreadable or invalid JSON")

    if not isinstance(payload, dict):
        return restrictive_policy(environment=environment, reason="policy root must be an object")

    overrides = payload.get("overrides", {})
    effective_payload = dict(payload)
    if isinstance(overrides, Mapping):
        env_override = overrides.get(environment, {})
        if isinstance(env_override, Mapping):
            effective_payload = _deep_merge(effective_payload, env_override)
    effective_payload.pop("overrides", None)

    runtime_policy = build_runtime_policy(environment=environment, payload=effective_payload)
    if not runtime_policy.valid:
        reason = "; ".join(runtime_policy.validation_errors) if runtime_policy.validation_errors else "policy validation failed"
        return restrictive_policy(environment=environment, reason=reason)
    return runtime_policy
