# Evidence Pack

<<<<<<< HEAD
This folder contains reviewer-ready evidence artifacts for security, client, and launch-readiness review.
=======
This folder contains reviewer-ready evidence artifacts for security review, launch review, and portfolio presentation.
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)

## Contents
- `architecture_summary.md`
- `control_summary.md`
<<<<<<< HEAD
- `policy_summary.md`
- `eval_summary.md`
- `telemetry_audit_summary.md`
=======
- `trust_boundary_summary.md`
- `threat_model_summary.md`
- `policy_summary.md`
- `retrieval_security_summary.md`
- `tool_authorization_summary.md`
- `telemetry_audit_summary.md`
- `eval_summary.md`
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)
- `launch_gate_summary.md`
- `residual_risks.md`
- `open_issues.md`

## How to Use
1. Run tests, evals, and launch gate.
<<<<<<< HEAD
2. Update this pack with current outputs and observations.
3. Attach the folder (or exported PDF bundle) during security/client review.
=======
2. Run `./scripts/check_evidence_pack.sh` to verify required evidence docs are present.
3. Update this pack with current outputs and observations.
4. Attach the folder (or exported PDF bundle) during security/client/portfolio review.
>>>>>>> 6d03c87 (harden launch-gate retrieval-boundary consistency verification)

## Evidence Integrity Notes
- Do not claim controls that are not implemented.
- Include command outputs and artifact paths where applicable.
- Mark assumptions and limitations explicitly in `residual_risks.md` and `open_issues.md`.
