# AGENTS.md - Engineering Guidance

Scope: Entire repository.

## Mission
Build a secure, production-oriented support-agent system incrementally, prioritizing correctness, safety, and auditability over speed.

## Core Guardrails
1. Do not bypass policy checks in new execution paths.
2. Do not add direct tool invocation paths from user input.
3. Do not introduce unreviewed data egress from sensitive contexts.
4. Do not claim security controls that are not implemented and tested.
5. Ensure every major decision point can be logged/audited.

## Implementation Expectations
- Keep module boundaries strict:
  - `app/` orchestrates flows.
  - `retrieval/` handles retrieval abstractions.
  - `tools/` defines tool contracts and registry behavior.
  - `policies/` defines policy models and enforcement interfaces.
  - `telemetry/audit/` defines audit schema and event pipeline interfaces.
  - `evals/` contains quality/safety evaluation harnesses.
  - `launch_gate/` contains release-readiness checks and criteria.
- Favor interface-first design with typed contracts before provider-specific code.
- Add tests with any non-trivial behavior.
- Keep docs aligned with actual implementation status.

## Safe Defaults
- Use deny-by-default where policy state is unknown.
- Use explicit allowlists for tools and retrieval sources.
- Attach request IDs and actor metadata to all major events.
- Fail closed when critical policy/telemetry dependencies are unavailable.

## Review Checklist (for future phases)
- [ ] Threat model updated for changed data flows.
- [ ] New code paths include policy checkpoints.
- [ ] New code paths include telemetry/audit hooks.
- [ ] Tests cover success and failure modes.
- [ ] Documentation updated to reflect true behavior.
