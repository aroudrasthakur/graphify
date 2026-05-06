# Runbook: evaluation harness

## Purpose

Quantify detector usefulness with **labeled fixtures**, not only “does it run”.

## Python API

- **Metrics:** `depos.eval.metrics` — `precision_recall`, `f1_score`, `recall_at_k`.
- **Reports:** `depos.eval.report` — `build_eval_report`, `write_eval_report` → `eval_report.json` shape with `content_sha256` for determinism checks.

## Fixtures

- Example label file: `tests/fixtures/eval/golden_labels.json`
- Tests: `tests/eval/test_detector_eval_golden.py`, `tests/eval/test_pipeline_recall_at_k.py`, `tests/eval/test_eval_report.py`
- Perf smoke: `tests/perf/test_pipeline_runtime_budget.py`

## Suggested workflow

1. Capture a **violations.json** + **run_manifest.json** from a known repo snapshot.
2. Maintain expected detector IDs / witness paths in a small JSON label file.
3. In CI, compare predicted detector hits to labels; assert recall@k and F1 floors.

See also `docs/dataset-pipeline.md` for end-to-end dataset normalization + pipeline.
