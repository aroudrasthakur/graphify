"""Precision/recall/F1 and recall@k helpers for labeled fixture evaluation."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Hashable, TypeVar

T = TypeVar("T", bound=Hashable)


def precision_recall(predicted_positive: set[T], actual_positive: set[T]) -> dict[str, float]:
    """Binary metrics with ``predicted_positive`` as detector output and ``actual_positive`` as labels."""
    tp = len(predicted_positive & actual_positive)
    fp = len(predicted_positive - actual_positive)
    fn = len(actual_positive - predicted_positive)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"tp": float(tp), "fp": float(fp), "fn": float(fn), "precision": precision, "recall": recall}


def f1_score(predicted_positive: set[T], actual_positive: set[T]) -> float:
    m = precision_recall(predicted_positive, actual_positive)
    p, r = m["precision"], m["recall"]
    if p + r == 0:
        return 0.0
    return 2 * p * r / (p + r)


def recall_at_k(ranked: Iterable[T], positives: set[T], k: int) -> float:
    """Fraction of ``positives`` that appear in the first ``k`` entries of ``ranked``."""
    if k <= 0 or not positives:
        return 0.0
    seen = set(list(ranked)[:k])
    return len(seen & positives) / len(positives)
