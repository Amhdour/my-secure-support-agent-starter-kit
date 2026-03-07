# Architecture Summary

## Scope
This starter kit implements a modular secure-support-agent runtime with policy, retrieval, tool mediation, telemetry/audit, eval harnesses, and launch-gate checks.

## Implemented Runtime Components
- `app/`: orchestration entrypoint and structured request/response/context modeling.
- `policies/`: policy schema, loader, and runtime policy decisions.
- `retrieval/`: source-registered, tenant-aware retrieval boundaries.
- `tools/`: centralized registry and mediated tool routing decisions.
- `telemetry/audit/`: typed events, JSONL sinks, replay artifacts.
- `evals/`: scenario-driven security evaluation harness.
- `launch_gate/`: machine-checkable readiness evaluator.

## Key Runtime Flow
1. Request normalization and trace context creation.
2. Policy checks gate retrieval/model/tool routing stages.
3. Retrieval enforces tenant/source and metadata boundaries.
4. Tool mediation enforces allowlist/deny/confirmation/rate limits.
5. Telemetry emits auditable events and replay-friendly artifacts.
6. Eval + launch-gate artifacts drive readiness outputs.
