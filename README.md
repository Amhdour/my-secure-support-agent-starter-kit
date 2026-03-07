# Secure Support Agent Starter Kit

A production-oriented repository scaffold for building a **secure support agent** with retrieval-augmented generation (RAG), policy enforcement, telemetry/audit trails, evaluations, and launch gating.

> Phase 10 adds a hardening and cleanup pass focused on safer defaults, tighter fail-safe behavior, and clearer deployment/demo readiness guidance.

## Purpose

This starter kit provides a clean foundation to:
- Build support-focused agent workflows incrementally.
- Separate concerns across app, retrieval, tools, policies, telemetry, evals, and launch controls.
- Enable safe iteration with clear extension points and test scaffolding.

## Current Scope

Included:
- Modular repository layout.
- Structured request/response/context models.
- Policy-aware orchestration flow with explicit stage boundaries.
- Secure retrieval service with source registration and tenant/source enforcement.
- Trust/provenance metadata requirements for citation-friendly retrieval results.
- Secure tool router with explicit allow/deny/require_confirmation decisions and mediated execution path.
- Policy-as-code runtime engine with validation, risk tiers, environment overrides, kill switch, and fallback-to-RAG handling.
- Structured telemetry and audit pipeline with JSONL output and replay artifact generation.
- Reusable security eval runner with scenario-based red-team cases and regression outputs.
- Launch-gate readiness evaluator with machine-checkable checks, blockers, and residual-risk summaries.
- Evidence-pack and reviewer/operator/portfolio documentation for practical review workflows.
- Hardening pass across policy/retrieval/tool/launch-gate fail-safe behavior and stricter tests.
- Environment/config templates.
- Engineering and safety guidance in `AGENTS.md`.
- Baseline and orchestration-focused tests.

Not included:
- Business/domain logic.
- Live integrations (LLM providers, vector stores, ticketing systems, etc.).
- Security claims beyond what is actually implemented.

## Repository Layout

```text
.
├── app/                  # Agent models, context, orchestration, model contracts
├── retrieval/            # Retrieval abstractions, indexing/query contracts
├── tools/                # Tool registry and mediated routing contracts
├── policies/             # Policy specs and enforcement integration points
├── telemetry/
│   └── audit/            # Audit event schemas and telemetry pipeline hooks
├── evals/                # Evaluation harness and datasets placeholders
├── launch_gate/          # Pre-launch readiness checks and release gate scaffolding
├── docs/                 # Architecture, roadmap, and operating docs
├── tests/                # Unit/integration/e2e structure and fixtures
├── artifacts/
│   └── logs/             # Runtime and CI artifact output location
├── config/               # Config templates and environment-specific overlays
└── scripts/              # Utility scripts for setup/validation (safe, non-prod)
```

## Core Flow (Phase 10)

1. Request enters with `SupportAgentRequest` and `SessionContext`.
2. Orchestrator builds `RequestContext`.
3. Policy gate checks retrieval stage.
4. Retrieval returns supporting documents.
5. Policy gate checks model generation stage.
6. Model receives user input plus retrieved context (RAG-first prompt envelope).
7. Policy gate checks tool-routing stage.
8. Tool router returns **decisions only** (never direct execution).
9. Response returns structured output + trace for auditability.

## Quick Start

1. **Create a virtual environment** (example with Python):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. **Install baseline dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. **Copy environment template**:
   ```bash
   cp .env.example .env
   ```
4. **Review config templates** in `config/` and adapt for your environment.
5. **Run tests**:
   ```bash
   pytest
   ```
6. **Run baseline security eval scenarios**:
   ```bash
   python -m evals.runner
   ```
7. **Run launch gate readiness evaluation**:
   ```bash
   python -m launch_gate.engine
   ```

## Development Principles

- Keep all execution paths policy-aware and auditable.
- Prefer explicit contracts between modules.
- Add implementation only with tests and documented threat considerations.
- Never claim security properties that are not verifiably implemented.

## Phase 10 Hardening Notes

- Retrieval and tool-routing now fail closed when policy evaluation errors occur.
- Tool decision outputs keep argument shape while redacting argument values to reduce leakage risk.
- Launch-gate evaluation now treats unreadable required evidence files as explicit blockers.


## Documentation & Evidence Pack

<<<<<<< HEAD
=======
- Architecture deep-dive: `docs/architecture.md`
- Architecture diagrams: `docs/architecture_diagrams.md`
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
- Operator/developer setup: `docs/operator/setup.md`
- Security reviewer guide: `docs/reviewer/security_review_guide.md`
- Portfolio summary: `docs/portfolio/project_summary.md`
- Evidence pack index: `docs/evidence_pack/README.md`
