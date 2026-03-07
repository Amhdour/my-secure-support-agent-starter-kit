#!/usr/bin/env bash
set -euo pipefail

required=(
  app
  retrieval
  tools
  policies
  telemetry/audit
  evals
  launch_gate
  docs
  tests
  artifacts/logs
  config
)

for path in "${required[@]}"; do
  if [[ ! -d "$path" ]]; then
    echo "Missing: $path"
    exit 1
  fi
done

echo "Scaffold check passed."
