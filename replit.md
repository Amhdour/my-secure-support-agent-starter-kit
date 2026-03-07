# Secure Support Agent Starter Kit

## Overview
A production-oriented scaffold for building a secure support agent with RAG, policy enforcement, telemetry/audit trails, evaluations, and launch gating. Pure Python backend — no frontend.

## Architecture
- **app/**: Agent models, context, orchestration
- **retrieval/**: Retrieval abstractions and service with tenant/source enforcement
- **tools/**: Tool registry, secure router, rate limiter
- **policies/**: Policy-as-code engine with validation and risk tiers
- **telemetry/audit/**: JSONL audit pipeline and replay artifacts
- **evals/**: Security eval runner with scenario-based red-team cases
- **launch_gate/**: Release readiness checker
- **tests/**: Unit, integration, and e2e tests (48 tests)
- **config/**: YAML config templates (settings, logging)
- **artifacts/logs/**: Runtime and CI artifact output

## Setup
- Language: Python 3.12
- Dependencies: `pytest==8.3.3` (only dev dependency)
- Environment: All config vars set via Replit Environment tab. See `.env.example` for reference.

## Environment Configuration
All current variables are non-sensitive CONFIG values with safe defaults. No real secrets are required to run the scaffold.

**Config variables** (set in Replit Environment, shared):
- ENVIRONMENT, LOG_LEVEL, APP_HOST, APP_PORT, REQUEST_TIMEOUT_SECONDS
- RETRIEVAL_BACKEND, RETRIEVAL_TOP_K, RETRIEVAL_INDEX_PATH
- TOOLS_ALLOWLIST, TOOL_EXECUTION_ENABLED
- POLICY_MODE, POLICY_BUNDLE_PATH
- TELEMETRY_ENABLED, AUDIT_SINK, AUDIT_LOG_PATH
- LAUNCH_GATE_STRICT

**Future secrets** (add via Replit Secrets when integrating real providers):
- LLM_API_KEY, VECTOR_STORE_URL, VECTOR_STORE_API_KEY
- TICKETING_API_KEY, WEBHOOK_SECRET

Note: The codebase does not currently read from os.environ. Environment variables are documented for future integration phases. Configuration is currently driven by policy JSON bundles and in-code dataclass defaults.

## Workflow
The "Start application" workflow runs:
1. `python3 -m pytest` — runs all 48 tests
2. `python3 -m evals.runner` — runs security evaluation scenarios
3. `python3 -m launch_gate.engine` — checks launch readiness

Output type: console (no web server/port).

## Key Principles
- Deny-by-default policy behavior
- All execution paths are policy-aware and auditable
- Fail-closed when critical dependencies are unavailable
- Tool decisions returned, never directly executed from user input
- Argument values redacted in tool decision outputs
