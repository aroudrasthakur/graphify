from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.context_bundle import build_bundle
from depos.analysis.detectors import run_all
from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import AnalysisMode, ChangeManifest
from depos.analysis.verifier import verify_all


def _graph(defined: bool) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node("code::reader", label="process.env.MISSING_SECRET", source_file="apps/web/app/page.tsx")
    graph.add_node(
        "env::MISSING_SECRET@apps/web/.env.local",
        node_kind="env_var",
        universe="env",
        name="MISSING_SECRET",
        label="MISSING_SECRET",
        defined=defined,
        source_file="apps/web/.env.local",
    )
    graph.add_edge("code::reader", "env::MISSING_SECRET@apps/web/.env.local", relation="READS_ENV_VAR", source_system="code", target_system="env")
    return graph


def _rc(graph: nx.DiGraph, config: IntelligenceConfig) -> object:
    m = ChangeManifest()
    return build_run_context(graph, m, config=config)


def test_env_var_referenced_but_undefined_positive() -> None:
    g = _graph(False)
    cfg = IntelligenceConfig()
    candidates, _ = run_all(g, ChangeManifest(), AnalysisMode.full_repo_scan, cfg, run_context=_rc(g, cfg))
    assert any(candidate.detector_payload.detector_name == "env-var-referenced-but-undefined" for candidate in candidates)


def test_env_var_referenced_but_undefined_negative() -> None:
    g = _graph(True)
    cfg = IntelligenceConfig()
    candidates, _ = run_all(g, ChangeManifest(), AnalysisMode.full_repo_scan, cfg, run_context=_rc(g, cfg))
    assert all(candidate.detector_payload.detector_name != "env-var-referenced-but-undefined" for candidate in candidates)


def test_env_var_referenced_but_undefined_verifier_confirms() -> None:
    config = IntelligenceConfig()
    graph = _graph(False)
    candidates, _ = run_all(
        graph, ChangeManifest(), AnalysisMode.full_repo_scan, config, run_context=_rc(graph, config)
    )
    candidate = next(candidate for candidate in candidates if candidate.detector_payload.detector_name == "env-var-referenced-but-undefined")
    bundle = build_bundle(graph, candidate, config=config)
    audits, findings = verify_all(
        candidate=candidate,
        bundle=bundle,
        reasoner_outputs={},
        config=config,
        full_repo_scan=True,
    )

    assert audits[0].verifier_outcome.value == "confirmed"
    assert findings[0].detector_name == "env-var-referenced-but-undefined"
