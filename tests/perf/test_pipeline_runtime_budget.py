"""Smoke perf gate: trivial work completes within a generous budget."""
from __future__ import annotations

import time

from depos.eval.metrics import precision_recall


def test_metrics_compute_under_budget() -> None:
    t0 = time.perf_counter()
    s = set(range(200))
    precision_recall({1, 2, 3}, s)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, "sanity budget for in-memory metrics"
