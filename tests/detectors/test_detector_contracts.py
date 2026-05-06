"""Registry contracts and calibration for builtin detectors."""
from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors import load_builtin, list_detectors, run_all
from depos.analysis.detectors.builtin.common import infer_confirmation_tier
from depos.analysis.run_context import RunContext
from depos.analysis.schemas import AnalysisMode, ChangeManifest


def test_every_builtin_detector_has_version_and_semantic_contract() -> None:
    load_builtin()
    for spec in list_detectors():
        assert spec.name
        assert spec.version
        assert spec.verifier_checks is not None
        assert spec.confirmation_tier in {"formal", "approximate", "heuristic"}
        # semantic_requirement may be None (Group A) or cfg/dfg/taint
        assert spec.semantic_requirement in (None, "cfg", "dfg", "taint")


def test_infer_confirmation_tier_flags_approx_suffix() -> None:
    assert infer_confirmation_tier("off-by-one-approx") == "approximate"
    assert infer_confirmation_tier("sql-injection-approx") == "approximate"
    assert infer_confirmation_tier("env-var-referenced-but-undefined") == "formal"


def test_semantic_layer_skip_emits_stats_placeholder(tmp_path, monkeypatch) -> None:
    """When CFG/DFG/taint is unavailable for every node, cfg detectors record skip_reason."""
    load_builtin()
    monkeypatch.setenv("DEPOS_DATA", str(tmp_path / "d"))
    graph = nx.DiGraph()
    manifest = ChangeManifest(resolved_via="empty_graph")
    ctx = RunContext.empty(manifest=manifest)
    cfg = IntelligenceConfig(data_dir=tmp_path / "d")

    _candidates, stats = run_all(
        graph,
        manifest,
        AnalysisMode.full_repo_scan,
        cfg,
        run_context=ctx,
    )

    skipped = [s for s in stats if s.skip_reason == "semantic_layer_unavailable"]
    assert skipped, "expected at least one skipped cfg/dfg/taint detector on an empty graph"
    assert all(s.candidates_emitted == 0 for s in skipped)
