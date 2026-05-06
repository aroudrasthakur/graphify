"""Evaluation harness: metrics and reports for detector / pipeline fixtures."""

from depos.eval.metrics import (
    f1_score,
    precision_recall,
    recall_at_k,
)

__all__ = [
    "f1_score",
    "precision_recall",
    "recall_at_k",
]
