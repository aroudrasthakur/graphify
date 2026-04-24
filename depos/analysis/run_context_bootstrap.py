"""Apply semantic-layer enrichment to a graph and construct :class:`RunContext`."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import networkx as nx

from depos.analysis.run_context import GraphMetrics, RunContext


def apply_semantic_layer(
    graph: nx.DiGraph,
    manifest: Any,
    *,
    repo_root: Optional[Path] = None,
    config: Any = None,
) -> RunContext:
    """Populate metrics, seam index, and (Phase 1a) Python CFG/DFG/taint."""
    del config  # future: disable layers per config
    from depos.analysis.graph_metrics import compute_graph_metrics
    from depos.analysis.seams import build_seam_edge_index
    from depos.analysis.semantic_jsts import enrich_jsts_semantics
    from depos.analysis.semantic_python import enrich_python_semantics

    metrics = compute_graph_metrics(graph)
    seam_index = build_seam_edge_index(graph)

    ctx = RunContext(
        manifest=manifest,
        repo_root=repo_root,
        graph_metrics=metrics,
        seam_edge_index=seam_index,
    )
    enrich_python_semantics(graph, ctx, repo_root=repo_root)
    enrich_jsts_semantics(graph, ctx, repo_root=repo_root)
    return ctx
