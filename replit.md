# Secure Support Agent Starter Kit

## Overview
A production-oriented scaffold for building a secure support agent with RAG, policy enforcement, telemetry/audit trails, evaluations, and launch gating. Pure Python backend — no frontend.

## Architecture
- **app/**: Agent models, context, orchestration
- **retrieval/**: Retrieval abstractions and service
- **tools/**: Tool registry and secure routing contracts
- **policies/**: Policy-as-code engine with validation and risk tiers
- **telemetry/audit/**: JSONL audit pipeline
- **evals/**: Security eval runner with scenario-based red-team cases
- **launch_gate/**: Release readiness checker
- **tests/**: Unit, integration, and e2e tests (48 tests)
- **config/**: Config templates (copy `.env.example` to `.env`)
- **artifacts/logs/**: Runtime and CI artifact output

## Setup
- Language: Python 3.12
- Dependencies: `pytest==8.3.3` (only dev dependency)
- Environment: Copy `.env.example` to `.env` and adapt as needed

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
