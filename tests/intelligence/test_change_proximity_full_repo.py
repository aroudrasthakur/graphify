from __future__ import annotations

import networkx as nx

from depos.analysis.detectors.builtin.common import _compute_change_proximity
from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import ChangeManifest


def test_full_repo_change_proximity_uses_pagerank_when_no_diff() -> None:
    graph = nx.DiGraph()
    graph.add_edge("center", "leaf_a", relation="CALLS")
    graph.add_edge("center", "leaf_b", relation="CALLS")
    graph.add_edge("leaf_a", "center", relation="CALLS")
    graph.add_edge("leaf_b", "center", relation="CALLS")

    run_context = build_run_context(
        graph,
        ChangeManifest(entries=[], resolved_via="empty"),
        repo_root=None,
        config=None,
    )
    high_pagerank_node = max(
        run_context.graph_metrics.pagerank,
        key=run_context.graph_metrics.pagerank.get,
    )

    proximity = _compute_change_proximity([], high_pagerank_node, graph, run_context)

    assert proximity > 0.0
