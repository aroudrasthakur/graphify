"""``--strict`` exit codes for ``depos-intel analyze dataset-pipeline``.

The operator-facing table lives in ``docs/runbooks/reasoner-zero-findings.md``.
These tests pin the pure helper used at the end of a dataset run so CI and
docs stay aligned with ``depos/cli/analyze.py``.
"""
from __future__ import annotations

from depos.cli.analyze import (
    STRICT_EXIT_INGEST_ERROR,
    STRICT_EXIT_PATH_RESOLUTION,
    STRICT_EXIT_REASONER_FAILED,
    _strict_exit_code,
)


def test_strict_failed_reasoner_returns_two() -> None:
    assert (
        _strict_exit_code(
            reasoner_health="failed",
            resolution_summary={"files_total": 10, "files_resolved": 10},
        )
        == STRICT_EXIT_REASONER_FAILED
    )


def test_strict_degraded_reasoner_returns_two() -> None:
    assert (
        _strict_exit_code(
            reasoner_health="degraded",
            resolution_summary={"files_total": 0, "files_resolved": 0},
        )
        == STRICT_EXIT_REASONER_FAILED
    )


def test_strict_low_path_resolution_returns_three() -> None:
    assert (
        _strict_exit_code(
            reasoner_health="ok",
            resolution_summary={"files_total": 10, "files_resolved": 2},
        )
        == STRICT_EXIT_PATH_RESOLUTION
    )


def test_strict_ok_when_resolution_and_reasoner_healthy() -> None:
    assert _strict_exit_code(reasoner_health="ok", resolution_summary={"files_total": 0, "files_resolved": 0}) == 0
    assert (
        _strict_exit_code(reasoner_health="ok", resolution_summary={"files_total": 4, "files_resolved": 4}) == 0
    )


def test_strict_ingest_errors_return_four_before_other_checks() -> None:
    assert (
        _strict_exit_code(
            reasoner_health="failed",
            resolution_summary={"files_total": 10, "files_resolved": 0},
            ingest_errors=[{"file": "x.py", "detail": "parse"}],
        )
        == STRICT_EXIT_INGEST_ERROR
    )
