"""Opt-in embedding-ranked seed candidates (extension point for model backends)."""
from __future__ import annotations

from typing import Any

import networkx as nx

from depos.analysis.schemas import AnalysisMode, Candidate


def embedding_seed_candidates(
    graph: nx.DiGraph,
    config: Any,
    mode: AnalysisMode,
    *,
    ctx: dict[str, Any] | None = None,
) -> list[Candidate]:
    """Return extra candidates when :attr:`IntelligenceConfig.enable_embedding_seeds` is on.

    The default implementation returns an empty list; future versions may rank
    nodes with an embedding model without changing detector wiring.
    """
    _ = graph, config, mode, ctx
    return []


__all__ = ["embedding_seed_candidates"]
