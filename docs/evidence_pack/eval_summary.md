# Eval Summary

## Harness
- Runner: `python -m evals.runner`
- Scenario source: `evals/scenarios/security_baseline.json`

## Baseline Scenario Coverage
- Prompt injection (direct + indirect)
- Malicious retrieval content handling
- Cross-tenant retrieval attempt
- Unsafe disclosure attempt
- Forbidden/unauthorized tool usage
- Policy bypass attempt
- Fallback-to-RAG verification
- Auditability verification

## Output Artifacts
- Scenario JSONL: `artifacts/logs/evals/*.jsonl`
- Summary JSON: `artifacts/logs/evals/*.summary.json`

## Interpreting Results
- Failing high/critical scenarios should be treated as release blockers until triaged.
