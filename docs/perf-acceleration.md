# depOS Performance Acceleration

This document tracks the staged acceleration work from the Cursor plan.

## Phase 5 Cache

`depos/cache.py` is an additive depOS fragment cache. It does not replace
`graphify/cache.py`, which remains the extractor cache used by the vendored
graphify path.

Default depOS cache root:

```text
<DEPOS_DATA>/cache/
```

CLI knobs on `depos-intel analyze repo`, `diff`, and `dataset-pipeline`:

```text
--no-cache
--cache-dir PATH
--cache-clear
--no-parallel
--n-jobs N
--taint-n-jobs N
--cfg-dfg-n-jobs N
--bundle-n-jobs N
--no-expensive-metrics
--metrics-backend {networkx,rustworkx}
--profile PATH
```

`coverage` supports `--n-jobs` and `--no-parallel` (Wave B enrichers only).

The Phase 5 cache keys include explicit version dimensions:

- Extraction fragments: source file, file hash, language, depOS version,
  cache schema version, parser version, and `extractor_config_hash`.
- Enrichment fragments: source file, file hash, language, depOS version,
  cache schema version, and `ENRICHER_SCHEMA_VERSION`.
- Per-function semantic layers: function id, source file, function source hash,
  language, semantic version, and a version tuple.

The existing `graphify/cache.py` key is content-hash based and does not include
parser/tree-sitter version or extractor config. A parser upgrade can therefore
produce stale graphify cache hits until source files change. That cache is left
unchanged for compatibility; the depOS cache keys include those invalidation
inputs for newly cached fragment layers.

## Phase 7 — Graph indexes

After Python and JS/TS semantic enrichment, `build_run_context()` builds
`GraphIndexes` via `depos/analysis/graph_indexes.py` and stores it on
`RunContext.indexes` (node/edge lookups, file groupings, taint edge indices, and
similar). `map_diagnostics_to_nodes()` accepts an optional `indexes=` argument
to avoid a full-graph scan when callers already have a `RunContext`.

## Phase 8 — CFG / DFG / taint (compute → `GraphFragment` → merge)

**CFG + DFG:** `depos/analysis/semantic_cfg_dfg.py` builds each scope on a local
`nx.DiGraph`, converts it to a `GraphFragment` (`stage="semantic"`, `file_hash=scope_id`
for deterministic merge order when multiple scopes share a source file), and the main
thread calls `merge_fragments`. When `PerfConfig.cfg_dfg_n_jobs > 1`, scope work runs in
a `ThreadPoolExecutor`; merges run in graph iteration order.

**Taint:** `compute_*_taint_work` / `apply_taint_scope_work` in `depos/analysis/taint.py`;
parallel when `taint_n_jobs > 1`.

## Phase 9 — `PerfConfig` and cheaper metrics

`depos/analysis/config.py` defines `PerfConfig` (`taint_n_jobs`, `bundle_n_jobs`,
`graph_metrics_expensive`, `metrics_backend`) merged from environment variables
and CLI flags on `analyze repo` / `diff` / `dataset-pipeline` (`_perf_config_from_args`
in `depos/cli/analyze.py`).

| Variable | Effect |
| -------- | ------ |
| `DEPOS_PERF_TAINT_N_JOBS` | Thread pool size for per-scope taint compute (default 1). |
| `DEPOS_PERF_CFG_DFG_N_JOBS` | Thread pool size for per-scope CFG/DFG fragment compute (default 1). |
| `DEPOS_PERF_BUNDLE_N_JOBS` | Thread pool size for parallel `build_bundle` in the pipeline (default 1). |
| `DEPOS_PERF_GRAPH_METRICS_EXPENSIVE` | When `0`/`false`, skips betweenness, articulation points, and cross-language cycle enumeration in `compute_graph_metrics()`. |
| `DEPOS_PERF_METRICS_BACKEND` | `networkx` (default) or `rustworkx` for expensive betweenness when installed; otherwise falls back to NetworkX with a warning. |

Named entry points: `compute_cheap_graph_metrics()` and `compute_expensive_graph_metrics()`
in `depos/analysis/graph_metrics.py` (wrappers around `compute_graph_metrics(..., expensive=...)`).

`build_run_context(..., perf=...)` overrides env defaults for tests.

## Phase 10 — Product outputs (golden bytes)

Byte-stable JSON for the five product artifacts remains centralized in
`depos/analysis/product_outputs.py` (`json.dumps(..., indent=2)`). For CI stability,
`write_product_outputs(..., generated_at=...)` pins the timestamp.

Checked-in golden files live under `tests/fixtures/product_outputs_golden/`; byte
equality is asserted in `tests/analysis/test_product_outputs_golden.py`. Regenerate
those five JSON files after intentional schema or fixture changes (same
`generated_at` as in the test module). Structural coverage also remains in
`tests/analysis/test_product_outputs.py`.

## Determinism (taint / indexes)

`graph.graph["taint_edges"]` is sorted before indexes are built (scope id, line,
source, sink) so serial and parallel taint runs produce comparable ordering.
Equivalence is covered by `tests/intelligence/test_graph_indexes_and_perf.py`.
Reducer / fragment collision tests: `tests/intelligence/test_graph_fragments.py`.
