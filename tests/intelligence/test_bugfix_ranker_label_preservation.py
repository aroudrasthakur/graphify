r"""Regression: Group C candidates keep the emitting detector identity on the payload.

After the ``resolve_detector_spec`` refactor, ``detector_payload.category`` and
``detector_payload.detector_name`` both reflect the registered spec name
(e.g. ``command-injection-approx``). The verifier loads that spec so Group C
``verifier_checks`` (taint probes, etc.) actually run.

Legacy behavior forced ``detector_name='graph-anomaly'`` and stashed the real id
in ``ranking_metadata.matched_pattern``; that indirection is removed.
"""
from __future__ import annotations

import networkx as nx
import pytest

from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors import run_all
from depos.analysis.run_context import GraphMetrics, RunContext
from depos.analysis.schemas import AnalysisMode, Candidate, ChangeManifest, DetectorPayload, SeedType, TaintEdge


def _rc(graph: nx.DiGraph, config: IntelligenceConfig) -> RunContext:
    m = GraphMetrics()
    m._computed = True
    return RunContext(
        manifest=ChangeManifest(entries=[], resolved_via="empty"),
        graph_metrics=m,
        cfg_available={},
        dfg_available={},
        taint_edges_available={},
    )


@pytest.fixture
def graph_with_taint_edge() -> nx.DiGraph:
    graph = nx.DiGraph()
    source_node = "node:user_input"
    sink_node = "node:subprocess_call"
    graph.add_node(
        source_node,
        label="user_input",
        source_file="app/handlers.py",
        language="python",
        node_type="variable",
    )
    graph.add_node(
        sink_node,
        label="subprocess.run",
        source_file="app/handlers.py",
        language="python",
        node_type="function_call",
    )
    taint_edge = TaintEdge(
        source_node=source_node,
        sink_node=sink_node,
        intermediate_path=[source_node, sink_node],
        crosses_seam=False,
        source_chain="request.query_params['cmd']",
        sink_pattern="subprocess.run(cmd, shell=True)",
        scope=sink_node,
        line=42,
    )
    graph.graph["taint_edges"] = [taint_edge]
    return graph


def test_group_c_payload_carries_emitting_detector_name(graph_with_taint_edge: nx.DiGraph) -> None:
    config = IntelligenceConfig()
    manifest = ChangeManifest(entries=[], resolved_via="empty")
    m = GraphMetrics()
    m._computed = True
    run_context = RunContext(
        manifest=manifest,
        graph_metrics=m,
        cfg_available={},
        dfg_available={"node:subprocess_call": True},
        taint_edges_available={"node:subprocess_call": True},
    )
    candidates, _stats = run_all(
        graph_with_taint_edge,
        manifest,
        AnalysisMode.full_repo_scan,
        config,
        run_context=run_context,
    )
    cmd_injection_candidates = [
        c
        for c in candidates
        if c.seed_type == SeedType.graph_anomaly
        and c.detector_payload.detector_name == "command-injection-approx"
    ]
    assert len(cmd_injection_candidates) > 0, (
        "command-injection-approx should emit at least one wrapped candidate"
    )
    candidate = cmd_injection_candidates[0]
    assert candidate.detector_payload.category == "command-injection-approx"
    assert candidate.detector_payload.detector_name == "command-injection-approx"


def test_resolve_detector_spec_prefers_category_over_stale_detector_name() -> None:
    """Registry lookup uses ``category`` so verifier checks match the emitting spec."""
    from depos.analysis.detectors import resolve_detector_spec

    c = Candidate(
        candidate_id="c_test",
        scope_id="s",
        seed_type=SeedType.graph_anomaly,
        detector_payload=DetectorPayload(
            category="command-injection-approx",
            detector_name="legacy-wrong-name",
            raw={},
        ),
    )
    spec = resolve_detector_spec(c)
    assert spec is not None
    assert spec.name == "command-injection-approx"
    assert "taint_sinks_subprocess" in spec.verifier_checks


def test_resolve_detector_spec_falls_back_to_detector_name() -> None:
    from depos.analysis.detectors import resolve_detector_spec

    c = Candidate(
        candidate_id="c_test2",
        scope_id="s",
        seed_type=SeedType.diff_anchor,
        detector_payload=DetectorPayload(
            category="unknown",
            detector_name="phantom-dep",
            raw={},
        ),
    )
    spec = resolve_detector_spec(c)
    assert spec is not None
    assert spec.name == "phantom-dep"
