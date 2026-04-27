"""Byte-identical golden files for the five product artifacts (Phase 10)."""
from __future__ import annotations

from pathlib import Path

from depos.analysis.config import IntelligenceConfig
from depos.analysis.product_outputs import write_product_outputs
from depos.analysis.schemas import RunMode

from tests.analysis.test_product_outputs import _result

GOLDEN_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "product_outputs_golden"
GOLDEN_TS = "2026-01-15T12:00:00+00:00"
_FILENAMES = (
    "findings.json",
    "impact_paths.json",
    "triage_backlog.json",
    "mcp_context.json",
    "product_summary.json",
)


def test_product_outputs_match_golden_bytes(tmp_path: Path) -> None:
    """Golden bytes are pinned with write_product_outputs(..., generated_at=GOLDEN_TS).

    Regenerate files under tests/fixtures/product_outputs_golden/ after intentional
    product schema or fixture changes (see docs/perf-acceleration.md).
    """
    cfg = IntelligenceConfig(data_dir=tmp_path / "data")
    write_product_outputs(
        tmp_path,
        _result(),
        RunMode.full_repo,
        cfg,
        generated_at=GOLDEN_TS,
    )
    for name in _FILENAMES:
        expected = (GOLDEN_DIR / name).read_bytes()
        actual = (tmp_path / name).read_bytes()
        assert actual == expected, f"{name} differs from golden; regen if intentional"
