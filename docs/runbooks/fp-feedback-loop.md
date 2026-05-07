# False-positive feedback loop (detector precision)

This runbook describes the **deterministic** knobs added to reduce noise without an ML verifier.

## Rolling precision file

After each pipeline run, `merge_run_precision()` updates:

```text
<DEPOS_DATA>/detector_precision_rollup.json
```

Values are a smoothed estimate of `verified_confirmed / (verified_confirmed + verified_invalid)` per detector name. The prior rollup is loaded at the **start** of `run_modules_2_through_7` and exposed as:

- `IntelligenceConfig.detector_precision_rollup` (in-memory for the run)
- `DetectorRunStats.historical_precision` (per detector row in `violations.json`)

## Confidence dampening

In `DetectorHeuristicsConfig.confidence_floor_by_detector`, map detector id → minimum acceptable rolling precision (0..1). If the rollup value for that detector is **below** the floor, `_wrap_candidate` multiplies `detector_confidence` by **0.85** before recomputing the composite score.

## Stable finding IDs

Set `DEPOS_INTEL_STABLE_FINDING_IDS=1` (or `verifier.stable_finding_ids=True` on `IntelligenceConfig`) to use a **hash-based** `finding_id` keyed by detector, scope, seam edges, diff anchors, mode, and bug type. The previous concatenation id is stored on each finding as `finding_id_legacy` for allowlist migration.

## CI gate extras

- `depos gate --auto-suppress PATH` merges extra finding ids (JSON array or `{"finding_ids": [...]}`) into the suppression set alongside `.depOS/allowlist.json`.
- The gate honors **either** `finding_id` **or** `finding_id_legacy` when matching allowlist/suppress entries.

## CLI helpers

- `depos detector-stats --violations PATH` — print `detector_stats` from a run.
- `depos migrate-allowlist --allowlist PATH --mapping old_to_new.json [--output PATH]` — rewrite allowlist `finding_id` values after enabling stable ids.

See also [evaluation-harness.md](evaluation-harness.md) and [reasoner-performance.md](reasoner-performance.md).
