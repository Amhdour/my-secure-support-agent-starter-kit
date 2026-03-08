# Evidence Pack

This folder contains reviewer-ready evidence artifacts for security review, launch review, and portfolio presentation.

## Contents
- `architecture_summary.md`
- `control_summary.md`
- `trust_boundary_summary.md`
- `threat_model_summary.md`
- `policy_summary.md`
- `retrieval_security_summary.md`
- `tool_authorization_summary.md`
- `telemetry_audit_summary.md`
- `eval_summary.md`
- `launch_gate_summary.md`
- `residual_risks.md`
- `open_issues.md`

## How to Use
1. Run tests, evals, and launch gate.
2. Run `./scripts/check_evidence_pack.sh` to verify required evidence docs are present.
3. Update this pack with current outputs and observations.
4. Attach the folder (or exported PDF bundle) during security/client/portfolio review.

## Evidence Integrity Notes
- Do not claim controls that are not implemented.
- Include command outputs and artifact paths where applicable.
- Mark assumptions and limitations explicitly in `residual_risks.md` and `open_issues.md`.
