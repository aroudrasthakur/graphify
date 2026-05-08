# Runbook: depOS local CLI (v1)

## Goal

Run analysis from a checkout, produce a **stable run bundle** (artifacts + checksums), and read a single **gate** decision.

## Prereqs

```bash
pip install -e ".[depos,intelligence]"
```

`depos` pulls in **Pydantic**, **diskcache** (on-disk fragment cache for Module 1 / Module 2), and the API-oriented deps declared in `pyproject.toml`. Add **`supabase`** if you also run the local API against Supabase.

For faster repeat scans and large graphs, add the **`perf`** extra (`joblib`, `orjson`, `xxhash`, `rustworkx`, profilers):

```bash
pip install -e ".[depos,intelligence,perf]"
```

Or use **`pip install -r requirements-dev.txt`** from the repo root (includes `depos`, `supabase`, `mcp`, `perf`, and `pytest`).

To disable disk cache for a single run, pass **`--no-cache`**.

## Commands

- **Product entrypoint:** `depos --help` (console script from `pyproject.toml`).
- **Legacy / full surface:** `depos-intel --help` (unchanged subcommands).

### Repo scan

```bash
depos analyze repo --path /path/to/checkout --run-profile local
```

Machine-readable summary prints to **stdout**; progress to **stderr**.

### Diff-aware run

```bash
depos analyze diff --path /path/to/checkout --run-profile local
# optional: --diff-path /path/to/patch.diff
```

### Profiles

- `local` — local-first defaults (see `depos/cli/v1_profile.py`).
- `full` / `llm` — documented in CLI epilog and `.env.example`.
- **`--profile-preset`** (`pr-fast`, `nightly-deep`, `custom`) — performance / depth for graph metrics and seed budgets (orthogonal to `--run-profile`). See **[pipeline-tuning.md](pipeline-tuning.md)**.

## Artifacts

Under `$DEPOS_DATA/intelligence/<run_id>/` you should see at least:

- `violations.json` — findings, detector stats, embedded `dep_summary`
- `dep_report.json` — same dependency rollup as `dep_summary` (sidecar for tooling)
- `gate_result.json` — authoritative CI-style decision
- `run_manifest.json` — schema version, artifact checksums, CLI snapshot

Strict exit codes are documented in `docs/runbooks/reasoner-zero-findings.md` and `STRICT_EXIT_*` in `depos/cli/analyze.py`.

## Failure modes

- **Missing pipeline wiring** (cannot import `run_modules_2_through_7`): process exits **`3`** after printing to stderr; no “silent clean” run.

## See also

- [`evaluation-harness.md`](evaluation-harness.md) — metrics fixtures.
- [`local-viewer.md`](local-viewer.md) — optional API import of bundles.
- [`pipeline-tuning.md`](pipeline-tuning.md) — perf presets and env knobs.
- [`fp-feedback-loop.md`](fp-feedback-loop.md) — finding IDs and `depos detector-stats`.
