#!/usr/bin/env bash
set -euo pipefail

# Detect unresolved merge-conflict markers in tracked files.
conflicts=$(git grep -nE '^(<<<<<<< |=======|>>>>>>> )' -- . ':!*.lock' || true)

if [[ -n "$conflicts" ]]; then
  echo "Unresolved merge conflict markers detected:"
  echo "$conflicts"
  exit 1
fi

echo "No merge conflict markers detected."
