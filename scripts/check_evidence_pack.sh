#!/usr/bin/env bash
set -euo pipefail

required=(
  docs/evidence_pack/README.md
  docs/evidence_pack/architecture_summary.md
  docs/evidence_pack/trust_boundary_summary.md
  docs/evidence_pack/threat_model_summary.md
  docs/evidence_pack/policy_summary.md
  docs/evidence_pack/retrieval_security_summary.md
  docs/evidence_pack/tool_authorization_summary.md
  docs/evidence_pack/telemetry_audit_summary.md
  docs/evidence_pack/eval_summary.md
  docs/evidence_pack/launch_gate_summary.md
  docs/evidence_pack/residual_risks.md
  docs/evidence_pack/open_issues.md
)

missing=()
for file in "${required[@]}"; do
  [[ -f "$file" ]] || missing+=("$file")
done

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Missing evidence-pack files: ${missing[*]}"
  exit 1
fi

echo "Evidence-pack check passed."
