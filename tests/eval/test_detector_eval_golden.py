"""Golden label expectations vs simple derived sets (eval harness smoke)."""
from __future__ import annotations

import json
from pathlib import Path

from depos.eval.metrics import f1_score, recall_at_k

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "eval" / "golden_labels.json"


def test_golden_labels_fixture_loads() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert data["fixture_id"] == "golden-minimal"
    assert "expected_detectors" in data


def test_recall_at_k_and_f1_on_synthetic_sets() -> None:
    predicted = {"sql-injection-approx", "noise-detector"}
    actual = {"sql-injection-approx"}
    assert recall_at_k(["noise-detector", "sql-injection-approx", "x"], actual, k=2) == 1.0
    assert f1_score(predicted, actual) > 0.5
