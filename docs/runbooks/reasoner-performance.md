# Reasoner Performance

This runbook covers reasoner performance observability and Pass 2
detector-specific reasoner policy. Candidate generation, detector output,
candidate ordering, legacy verification/gating, timeout defaults, retry
defaults, token defaults, and concurrency are unchanged.

## Reading `reasoner_attempts.jsonl`

`reasoner_attempts.jsonl` is written next to the existing canonical run
artifacts such as `reasoner_queue.jsonl`, `observability.jsonl`, `prompts/`,
and ranker examples. It contains one `reasoner_attempt` record per provider
attempt, including successful attempts, failed attempts, retry-recovered
failures, and exhausted failures.

Each record includes the candidate, detector, mode, provider, model, attempt
index, actual timeout used, prompt size, requested output tokens, elapsed
provider-call milliseconds, success flag, failure details, and whether a failed
attempt was later recovered by retry.

`run_summary.json` includes `reasoner_attempt_summary`, a compact aggregate of
the same records: total attempts, successes, failures, recovered failures,
elapsed-time percentiles, timeout count, and per-detector breakdowns.

## Reading `reasoner_attempt_summary`

Use `reasoner_attempt_summary.total_attempts`, `successful_attempts`,
`failed_attempts`, `recovered_failures`, `timeouts`, and elapsed percentiles to
answer whether the reasoner is slow because each call is slow, because retries
are multiplying calls, or both. `provider` and `model` are the unique observed
values or `mixed` when a run used more than one.

The `by_detector` section shows which detector family consumed the attempts.
This is the fastest way to confirm patterns such as `graph_anomaly` dominating
a local Ollama run.

## Diagnosing Retry Amplification

Compare `bundles_sent_to_reasoner` with
`reasoner_attempt_summary.total_attempts`. If total attempts are much higher
than bundles sent, retries are amplifying runtime. Then inspect
`reasoner_attempt_summary.recovered_failures`, `timeouts`, and `by_detector` to
see which detector group is driving the extra calls.

For deeper inspection, group `reasoner_attempts.jsonl` by `candidate_id` and
`attempt_idx`. A pattern like many first attempts failing and second attempts
succeeding means the run is paying the timeout cost even when final health is
reported as `ok`.

## Ollama Timeout Calibration

If failed attempts cluster near the configured timeout, for example around the
Ollama subsequent-call timeout, that suggests timeout calibration or local model
throughput issues. If p90 successful attempt latency is around 190s, a 120s
subsequent timeout can create false transport failures. Raising the timeout can
reduce retry amplification, but it does not make a single model call faster.

Inspect p90/p95 in `reasoner_attempt_summary`, then set the configured Ollama
subsequent timeout near or above normal successful latency. Avoid setting a
timeout below the observed successful-call range.

Supported timeout env vars include the existing `DEPOS_LLM_OLLAMA_FIRST_CALL_TIMEOUT`
and `DEPOS_LLM_OLLAMA_SUBSEQUENT_TIMEOUT`; aliases
`DEPOS_OLLAMA_FIRST_CALL_TIMEOUT` and `DEPOS_OLLAMA_SUBSEQUENT_TIMEOUT` are also
accepted.

## Evidence Gating For Bulk Local Runs

`DEPOS_INTEL_MIN_EVIDENCE_SCORE` keeps low-evidence bundles from going to the
LLM reasoner. This does not remove candidates from `candidates.json`; it only
skips expensive LLM calls and records the skip in `bundle_pipeline_trace.json`.

For bulk local Ollama runs, start with:

```powershell
$env:DEPOS_INTEL_MIN_EVIDENCE_SCORE="0.3"
```

Use `bundle_pipeline_trace.json` to confirm skipped candidates remain visible.

## Detector-Specific Gating

Use detector-specific policy when one detector dominates runtime:

```powershell
$env:DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR="graph_anomaly:0.45"
$env:DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR="graph_anomaly:5"
```

To skip LLM reasoning entirely for a detector while preserving candidates and
bundles:

```powershell
$env:DEPOS_REASONER_DISABLED_DETECTORS="graph_anomaly"
```

Policy skips are recorded in `bundle_pipeline_trace.json` with
`reasoner_skipped`, `reasoner_skip_reason`, and `reasoner_skip_detail`.
`run_summary.json` includes `reasoner_policy_summary` with policy settings,
skip counts by reason, skip counts by detector, sent counts by detector, and
warnings.

## `graph_anomaly` Recommendations

`graph_anomaly` can produce many broad candidates. Keep those candidates for
visibility, but gate their LLM reasoning during bulk local runs:

```powershell
$env:DEPOS_INTEL_MIN_EVIDENCE_SCORE="0.3"
$env:DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR="graph_anomaly:0.45"
$env:DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR="graph_anomaly:5"
```

For triage-only graph anomaly runs:

```powershell
$env:DEPOS_REASONER_DISABLED_DETECTORS="graph_anomaly"
```

## Token Budget Recommendations

Local Ollama bulk runs should use smaller output token budgets when possible.
Large JSON-constrained outputs are often slow. Prompt budget and output budget
both affect runtime; use `prompt_chars`, `prompt_bytes`, and
`requested_output_tokens` in `reasoner_attempts.jsonl` to compare slow and fast
attempts.

This pass adds warnings for risky local Ollama profiles, but it does not change
the default prompt or output token budgets.

## Why Ollama Concurrency Defaults To 1

This pass does not add parallelism. Local single-GPU Ollama often queues
concurrent requests internally; increasing client concurrency can worsen
latency and increase timeout pressure. Keep local Ollama concurrency at 1 unless
your hardware and model server support real parallel inference. Remote providers
can consider bounded parallelism in a later pass.

## Suggested Local Ollama Bulk Profile

```powershell
$env:DEPOS_INTEL_MIN_EVIDENCE_SCORE="0.3"
$env:DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR="graph_anomaly:0.45"
$env:DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR="graph_anomaly:5"
```

Then inspect `reasoner_attempt_summary.p90_attempt_ms`,
`reasoner_attempt_summary.p95_attempt_ms`, and `reasoner_policy_summary` to
tune the next run.
