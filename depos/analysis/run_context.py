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

from depos.analysis.config import PerfConfig

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
    run_id: str = ""
    repo_root: Optional[Path] = None
    graph_metrics: Optional[GraphMetrics] = None
    seam_edge_index: dict[str, Any] = field(default_factory=dict)
    # scope node id (function / method entity) -> whether analysis succeeded
    cfg_available: dict[str, bool] = field(default_factory=dict)
    dfg_available: dict[str, bool] = field(default_factory=dict)
    taint_edges_available: dict[str, bool] = field(default_factory=dict)
    perf: PerfConfig = field(default_factory=PerfConfig)
    indexes: Any = None  # GraphIndexes | None

    @staticmethod
    def empty(*, manifest: Any = None) -> RunContext:
        return RunContext(manifest=manifest)

    def graph_metrics_or_raise(self) -> GraphMetrics:
        if self.graph_metrics is None:
            raise RuntimeError("RunContext.graph_metrics is unset — semantic layer not applied.")
        self.graph_metrics.require_computed()
        return self.graph_metrics


def _sort_taint_edges_inplace(graph: nx.DiGraph) -> None:
    te = graph.graph.get("taint_edges")
    if not te:
        return

    def _key(e: Any) -> tuple[str, int, str, str]:
        if hasattr(e, "scope"):
            return (
                str(e.scope),
                int(e.line or 0),
                str(e.source_node),
                str(e.sink_node),
            )
        if isinstance(e, dict):
            return (
                str(e.get("scope", "")),
                int(e.get("line") or 0),
                str(e.get("source_node", "")),
                str(e.get("sink_node", "")),
            )
        return ("", 0, "", "")

    te.sort(key=_key)


def build_run_context(
    graph: nx.DiGraph,
    manifest: Any,
    *,
    run_id: str = "",
    repo_root: Optional[Path] = None,
    config: Any = None,  # IntelligenceConfig; reserved for future gating
    perf: Optional[PerfConfig] = None,
) -> RunContext:
    """Build a :class:`RunContext` and apply the semantic layer (GraphMetrics, seams, …).

    Phase 0: manifest + empty placeholder metrics only.
    Phase 1a: full Python CFG/DFG/taint and metrics.
    """
    from depos.analysis.config import load_perf_config_from_env
    from depos.analysis.graph_indexes import build_graph_indexes
    from depos.analysis.graph_metrics import compute_graph_metrics
    from depos.analysis.seams import build_seam_edge_index
    from depos.analysis.semantic_jsts import enrich_jsts_semantics
    from depos.analysis.semantic_python import enrich_python_semantics

    perf_resolved = perf or load_perf_config_from_env()
    metrics = compute_graph_metrics(
        graph,
        expensive=perf_resolved.graph_metrics_expensive,
        metrics_backend=perf_resolved.metrics_backend,
    )
    seam_index = build_seam_edge_index(graph)

    ctx = RunContext(
        manifest=manifest,
        run_id=run_id,
        repo_root=repo_root,
        graph_metrics=metrics,
        seam_edge_index=seam_index,
        perf=perf_resolved,
    )
    enrich_python_semantics(graph, ctx, repo_root=repo_root)
    enrich_jsts_semantics(graph, ctx, repo_root=repo_root)
    _sort_taint_edges_inplace(graph)
    ctx.indexes = build_graph_indexes(graph)
    return ctx


__all__ = [
    "GraphMetrics",
    "RunContext",
    "build_run_context",
]
