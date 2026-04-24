"""Policy gate: run_all and Group B/C runners route through ``iter_eligible_scopes``."""
from __future__ import annotations

import networkx as nx

import depos.analysis.detectors as det_pkg
from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors import REGISTRY, load_builtin, run_all
from depos.analysis.detectors import policy as detector_policy
from depos.analysis.detectors.builtin import group_b_cfg_detectors as gb
from depos.analysis.detectors.builtin import group_c_taint_dfg_detectors as gc
from depos.analysis.run_context import GraphMetrics, RunContext
from depos.analysis.schemas import AnalysisMode, ChangeManifest


def _semantically_gated_names() -> set[str]:
    load_builtin()
    return {spec.name for spec, _ in REGISTRY.values() if spec.semantic_requirement is not None}


def _wrap_iter_eligible(calls: list[str], real):
    def w(graph, ctx, spec):
        calls.append(spec.name)
        yield from real(graph, ctx, spec)

    return w


def test_run_all_and_bc_runners_invoked_iter_eligible_scopes(monkeypatch) -> None:
    real = detector_policy.iter_eligible_scopes
    calls: list[str] = []
    w = _wrap_iter_eligible(calls, real)
    monkeypatch.setattr(detector_policy, "iter_eligible_scopes", w)
    monkeypatch.setattr(det_pkg, "iter_eligible_scopes", w)
    monkeypatch.setattr(gb, "iter_eligible_scopes", w)
    monkeypatch.setattr(gc, "iter_eligible_scopes", w)

    g = nx.DiGraph()
    g.add_node("scope1")
    m = GraphMetrics()
    m._computed = True
    rctx = RunContext(
        manifest=ChangeManifest(),
        graph_metrics=m,
        cfg_available={"scope1": True},
        dfg_available={"scope1": True},
        taint_edges_available={"scope1": True},
    )
    cfg = IntelligenceConfig()
    run_all(g, ChangeManifest(), AnalysisMode.full_repo_scan, cfg, run_context=rctx)

    expected = _semantically_gated_names()
    pol = detector_policy.DetectorPolicy()
    for name, (spec, _) in REGISTRY.items():
        if not pol.is_enabled(spec):
            expected.discard(name)

    for n in expected:
        assert n in calls, f"iter_eligible_scopes not exercised for semantic detector {n!r}"
