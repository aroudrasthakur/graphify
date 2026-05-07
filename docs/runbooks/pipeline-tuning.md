# Pipeline tuning runbook

Quick reference for **stable, repeatable** `depos analyze` runs across laptop and CI.

## Presets (`--run-profile` / `--profile-preset`)

| Preset | Reasoner | Gray zone | Typical use |
|--------|----------|-----------|-------------|
| `local` | Stub when unset | Off when unset | Fast feedback / unit-style graphs |
| `full` | From env | From env | Default team/CI |
| `llm` | From env | On when unset | Max signal, higher cost |

Both flags are equivalent; `--profile-preset` exists as an ergonomic alias.

## Large graphs

See [`docs/perf-acceleration.md`](../perf-acceleration.md) for `DEPOS_PERF_*`, fragment cache behavior, auto-downgrade of expensive graph metrics (logged at **INFO** in `build_run_context()` with node/edge counts), and `--shard-by package_manifest`.

## Detector budget

- `DEPOS_REASONER_DISABLED_DETECTORS` — comma-separated list to skip expensive reasoner-backed detectors in CI smoke runs.
- `--detectors exclude=name` on the CLI (see `depos analyze --help`).

## Cache hygiene

- `--cache-clear` wipes `<DEPOS_DATA>/cache` before a run.
- `--cache-dir` redirects the fragment store (useful on CI ephemeral disks).

## When results look “too empty”

1. Confirm Module 1 stitcher coverage in run metadata / logs.
2. Confirm detectors weren’t excluded via policy env or CLI.
3. For monorepos, try `--shard-by none` (default) if manifest-scoped detection removed too many nodes.
