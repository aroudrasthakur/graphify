"""eval_report.json builder determinism."""
from __future__ import annotations

from pathlib import Path

from depos.eval.report import build_eval_report, write_eval_report


def test_eval_report_content_hash_stable(tmp_path: Path) -> None:
    r1 = build_eval_report(
        fixture_id="f1",
        metrics={"precision": 0.8, "recall": 0.7},
        timings_sec={"pipeline": 1.25},
    )
    r2 = build_eval_report(
        fixture_id="f1",
        metrics={"precision": 0.8, "recall": 0.7},
        timings_sec={"pipeline": 1.25},
    )
    assert r1["content_sha256"] == r2["content_sha256"]
    out = tmp_path / "eval_report.json"
    write_eval_report(out, r1)
    assert out.is_file()
    assert "content_sha256" in out.read_text(encoding="utf-8")
