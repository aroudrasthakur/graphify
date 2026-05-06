"""Emit ``eval_report.json``-shape summaries for local evaluation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _stable_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def build_eval_report(
    *,
    fixture_id: str,
    metrics: dict[str, Any],
    timings_sec: dict[str, float] | None = None,
    artifact_paths: dict[str, str] | None = None,
    schema_version: str = "1.0",
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": schema_version,
        "fixture_id": fixture_id,
        "metrics": metrics,
        "timings_sec": dict(timings_sec or {}),
        "artifacts": dict(artifact_paths or {}),
    }
    report["content_sha256"] = hashlib.sha256(_stable_json({k: report[k] for k in ("fixture_id", "metrics", "timings_sec")})).hexdigest()
    return report


def write_eval_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
