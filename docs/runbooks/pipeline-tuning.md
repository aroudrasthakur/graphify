# Pipeline tuning runbook

Quick reference for **stable, repeatable** `depos analyze` runs across laptop and CI.

Two preset mechanisms are **orthogonal**:

| Knob | Command flag | Values | What it changes |
|------|----------------|--------|-----------------|
| **V1 analysis profile** | `--run-profile` | `local`, `full`, `llm` | Env-oriented defaults for **reasoner provider / gray-zone** (see `depos/cli/v1_profile.py`) before `load_config_from_env`. |
| **Performance / depth preset** | `--profile-preset` | `pr-fast`, `nightly-deep`, `custom` | **PerfConfig** (expensive graph metrics, metrics backend) and **candidate budget** (`pr-fast` caps `max_seeds` unless you pass `--max-seeds`). |

**Precedence (reasonable defaults):** explicit CLI flags (e.g. `--no-expensive-metrics`, `--metrics-backend`, `--max-seeds`) and `DEPOS_*` env when set **win** over `--profile-preset` overlays. For `graph_metrics_expensive` and `metrics_backend`, a preset only fills in when the corresponding env var is **unset** (`DEPOS_PERF_GRAPH_METRICS_EXPENSIVE`, `DEPOS_PERF_METRICS_BACKEND`).

## V1 analysis profiles (`--run-profile`)

| Preset | Reasoner | Gray zone | Typical use |
|--------|----------|-----------|-------------|
| `local` | Stub when unset | Off when unset | Fast feedback / unit-style graphs |
| `full` | From env | From env | Default team/CI |
| `llm` | From env | On when unset | Max signal, higher cost |

Example:

```bash
depos analyze repo --path . --run-profile local
```

## Performance presets (`--profile-preset`)

| Preset | Graph metrics | Backend hint | Candidate budget |
|--------|----------------|--------------|------------------|
| `custom` | From env / flags only | From env / flags | From config |
| `pr-fast` | Cheap (no betweenness / articulation / cross-lang cycles) when `DEPOS_PERF_GRAPH_METRICS_EXPENSIVE` is unset | Unchanged | Caps `max_seeds` at **50** unless `--max-seeds` is passed (repo/diff); respects existing config if already lower |
| `nightly-deep` | Expensive path on when `DEPOS_PERF_GRAPH_METRICS_EXPENSIVE` is unset | Prefers **rustworkx** when env and `--metrics-backend` are both unset (falls back if unavailable) | From config |

Use `pr-fast` for **PR / pre-merge** scans; use `nightly-deep` for **scheduled** or deep repo runs where you want full topology metrics and a faster centrality backend when installed.

## Profiling

- **`--pyinstrument-html PATH`** — CPU flame graph HTML for `repo` / `diff` / `dataset-pipeline` (optional extra: `graphifyy[perf]`).
- Logs: `build_run_context` emits an **INFO** line at the start (nodes, edges, expensive-metrics decision) and a **final summary after semantics** with `nodes`, `edges`, and **`taint_edges`** count.

## Large graphs and sharding

See [`docs/perf-acceleration.md`](../perf-acceleration.md) for `DEPOS_PERF_*`, fragment cache behavior, auto-downgrade of expensive graph metrics (large `DEPOS_PERF_GRAPH_METRICS_AUTO_DOWNGRADE_AT`), and `--shard-by package_manifest`.

## Detector budget and FP management

- `DEPOS_REASONER_DISABLED_DETECTORS` — comma-separated list to skip expensive reasoner-backed detectors in CI smoke runs.
- `--detectors exclude=name` on the CLI (see `depos analyze --help`).
- False-positive loop: see [`docs/runbooks/fp-feedback-loop.md`](fp-feedback-loop.md) for stable `finding_id`, allowlists, and `depos detector-stats`.

### Team worksheet (copy/paste)

| Run | `--run-profile` | `--profile-preset` | Notes |
|-----|-----------------|---------------------|--------|
| Local smoke | `local` | `pr-fast` | Stub reasoner + cheap metrics |
| CI PR | `full` | `pr-fast` | Match gate env; fast metrics |
| Nightly | `full` | `nightly-deep` | Install **rustworkx** for best centrality performance |
| Custom | `full` | `custom` | Only `DEPOS_*` + explicit flags |

## Cache hygiene

- `--cache-clear` wipes `<DEPOS_DATA>/cache` before a run.
- `--cache-dir` redirects the fragment store (useful on CI ephemeral disks).

## When results look “too empty”

1. Confirm Module 1 stitcher coverage in run metadata / logs.
2. Confirm detectors weren’t excluded via policy env or CLI.
3. For monorepos, try `--shard-by none` (default) if manifest-scoped detection removed too many nodes.
4. Confirm `pr-fast` did not starve the candidate cap; raise `--max-seeds` or use `--profile-preset custom`.
