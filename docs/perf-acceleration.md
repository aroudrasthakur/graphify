# Performance acceleration notes

This doc captures **large-graph** knobs that materially change Module 1–2 runtime.

## Environment knobs

| Variable | Effect |
|----------|--------|
| `DEPOS_PERF_GRAPH_METRICS_EXPENSIVE=0` | Skip betweenness sampling, articulation-point scan, and cross-language cycle enumeration in `compute_graph_metrics()`. |
| `DEPOS_PERF_GRAPH_METRICS_AUTO_DOWNGRADE_AT` | Node-count threshold (default **35000**). When the graph is larger and expensive metrics are on, `build_run_context()` logs an INFO line and runs the cheap metrics path automatically. |
| `DEPOS_PERF_TAINT_N_JOBS`, `DEPOS_PERF_CFG_DFG_N_JOBS`, `DEPOS_PERF_BUNDLE_N_JOBS` | Thread pools for semantic work and bundle materialization. |
| `DEPOS_CACHE_ENABLED` / `--no-cache` | Disables the on-disk fragment cache rooted at `<DEPOS_DATA>/cache`. |

## CLI: `--shard-by package_manifest`

`depos analyze repo|diff|dataset-pipeline ... --shard-by package_manifest` runs **Module 2 detection** (detectors + `build_run_context` metrics) on the union of nodes that live under any `package_manifest` workspace directory. **Module 3+ bundles** still read the **full** graph so snippets and seam context stay complete.

## Module 1: `emit_env_edges` cache

When caching is enabled, per-source-file env fragments are keyed by `build_enrichment_fragment_cache_key(..., stage="emit_env_edges", enricher_logic_version="env-v1")` so repeated scans skip re-reading unchanged files.

## Benchmark snapshot (informal)

On a mid-size fixture (~15k nodes, ~40k edges), turning off expensive metrics typically saves **tens of seconds** on NetworkX betweenness alone; the auto-downgrade path targets monolith graphs where full betweenness/articulation work is rarely worth the wall time. Re-benchmark on your hardware when tuning CI budgets.
