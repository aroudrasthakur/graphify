"""Recall@k on ranked candidate ids."""
from __future__ import annotations

from depos.eval.metrics import recall_at_k


def test_recall_at_k_partial_coverage() -> None:
    ranked = ["a", "b", "c", "d"]
    positives = {"b", "d"}
    assert recall_at_k(ranked, positives, k=2) == 0.5
    assert recall_at_k(ranked, positives, k=4) == 1.0


def test_recall_at_k_empty_positives() -> None:
    assert recall_at_k(["a", "b"], set(), k=2) == 0.0
