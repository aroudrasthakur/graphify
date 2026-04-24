"""Per-run context threaded through `identify_candidates` and every detector `run()`.

Holds the resolved change manifest, optional repo root for reading sources,
pre-computed :class:`GraphMetrics`, seam-edge index, and per-scope-node
availability flags for CFG / DFG / taint (populated in Phase 1a+).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import networkx as nx

if False:  # TYPE_CHECKING
    from depos.analysis.schemas import ChangeManifest


@dataclass
class GraphMetrics:
    """Graph topology and seam-oriented metrics (computed once per run)."""

    node_pagerank: dict[str, float] = field(default_factory=dict)
    betweenness: dict[str, float] = field(default_factory=dict)
    articulation_points: list[str] = field(default_factory=list)
    fan_in: dict[str, int] = field(default_factory=dict)
    fan_out: dict[str, int] = field(default_factory=dict)
    scc_count: int = 0
    scc_id_by_node: dict[str, int] = field(default_factory=dict)
    scc_size_by_node: dict[str, int] = field(default_factory=dict)
    cross_lang_cycles: list[list[str]] = field(default_factory=list)
    _computed: bool = False

    def require_computed(self) -> None:
        if not self._computed:
            raise RuntimeError("GraphMetrics requested before compute_graph_metrics() ran.")

    @property
    def pagerank(self) -> dict[str, float]:
        """Compatibility alias used by newer pipeline stages."""
        return self.node_pagerank


@dataclass
class RunContext:
    """Bundle passed to every detector via `ctx['run_context']`."""

    manifest: Any  # ChangeManifest; avoid import cycle
    repo_root: Optional[Path] = None
    graph_metrics: Optional[GraphMetrics] = None
    seam_edge_index: dict[str, Any] = field(default_factory=dict)
    # scope node id (function / method entity) -> whether analysis succeeded
    cfg_available: dict[str, bool] = field(default_factory=dict)
    dfg_available: dict[str, bool] = field(default_factory=dict)
    taint_edges_available: dict[str, bool] = field(default_factory=dict)

    @staticmethod
    def empty(*, manifest: Any = None) -> RunContext:
        return RunContext(manifest=manifest)

    def graph_metrics_or_raise(self) -> GraphMetrics:
        if self.graph_metrics is None:
            raise RuntimeError("RunContext.graph_metrics is unset — semantic layer not applied.")
        self.graph_metrics.require_computed()
        return self.graph_metrics


def build_run_context(
    graph: nx.DiGraph,
    manifest: Any,
    *,
    repo_root: Optional[Path] = None,
    config: Any = None,  # IntelligenceConfig; reserved for future gating
) -> RunContext:
    """Build a :class:`RunContext` and apply the semantic layer (GraphMetrics, seams, …).

    Phase 0: manifest + empty placeholder metrics only.
    Phase 1a: full Python CFG/DFG/taint and metrics.
    """
    from depos.analysis.run_context_bootstrap import apply_semantic_layer

    return apply_semantic_layer(graph, manifest, repo_root=repo_root, config=config)


__all__ = [
    "GraphMetrics",
    "RunContext",
    "build_run_context",
]
