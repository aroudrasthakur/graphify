"""One-shot graph metrics for :class:`RunContext` (Section 5.1)."""
from __future__ import annotations

import logging
from typing import Literal

import networkx as nx

from depos.analysis.run_context import GraphMetrics

logger = logging.getLogger(__name__)


def _betweenness_centrality_directed(
    g: nx.DiGraph,
    *,
    n: int,
    metrics_backend: Literal["networkx", "rustworkx"],
) -> dict[str, float]:
    if metrics_backend == "rustworkx":
        try:
            return _betweenness_rustworkx(g)
        except ImportError:
            logger.warning(
                "metrics_backend=rustworkx but rustworkx is not installed; using networkx"
            )
    if n <= 400:
        return {str(k): float(v) for k, v in nx.betweenness_centrality(g, normalized=True).items()}
    k = min(200, n)
    return {
        str(k): float(v)
        for k, v in nx.betweenness_centrality(g, k=k, normalized=True, seed=42).items()
    }


def _betweenness_rustworkx(g: nx.DiGraph) -> dict[str, float]:
    import rustworkx as rx

    r = rx.PyDiGraph()
    nx_to_rx: dict[object, int] = {}
    for nid in g.nodes():
        nx_to_rx[nid] = r.add_node(str(nid))
    seen: set[tuple[object, object]] = set()
    for u, v in g.edges():
        if (u, v) in seen:
            continue
        seen.add((u, v))
        r.add_edge(nx_to_rx[u], nx_to_rx[v], None)
    cent = rx.digraph_betweenness_centrality(r, normalized=True)
    out: dict[str, float] = {}
    for idx, score in cent.items():
        payload = r.get_node_data(idx)
        out[str(payload)] = float(score)
    return out


def compute_graph_metrics(
    graph: nx.DiGraph,
    *,
    expensive: bool = True,
    metrics_backend: Literal["networkx", "rustworkx"] = "networkx",
) -> GraphMetrics:
    """PageRank, fan-in/out, SCCs; optional betweenness, articulation points, cross-lang cycles."""
    g = graph
    n = g.number_of_nodes()
    if n == 0:
        out = GraphMetrics()
        out._computed = True
        return out

    try:
        pr = nx.pagerank(g, max_iter=100)
    except Exception:  # noqa: BLE001
        pr = {str(node): 1.0 / n for node in g.nodes()}

    betw: dict[str, float] = {}
    if expensive:
        betw = _betweenness_centrality_directed(g, n=n, metrics_backend=metrics_backend)

    fin: dict[str, int] = {}
    fout: dict[str, int] = {}
    for node in g.nodes():
        ns = str(node)
        fin[ns] = g.in_degree(node)
        fout[ns] = g.out_degree(node)

    scc = list(nx.strongly_connected_components(g))
    scc_id: dict[str, int] = {}
    scc_size: dict[str, int] = {}
    for i, comp in enumerate(scc):
        comp_size = len(comp)
        for node in comp:
            scc_id[str(node)] = i
            scc_size[str(node)] = comp_size

    articulation_points: list[str] = []
    if expensive:
        try:
            articulation_points = [
                str(node) for node in nx.articulation_points(g.to_undirected(as_view=True))
            ]
        except Exception:  # noqa: BLE001
            articulation_points = []

    cycles: list[list[str]] = _cross_language_cycles(g) if expensive else []

    metrics = GraphMetrics(
        node_pagerank={str(k): float(v) for k, v in pr.items()},
        betweenness=betw,
        articulation_points=articulation_points,
        fan_in=fin,
        fan_out=fout,
        scc_count=len(scc),
        scc_id_by_node=scc_id,
        scc_size_by_node=scc_size,
        cross_lang_cycles=cycles,
    )
    metrics._computed = True
    return metrics


def compute_cheap_graph_metrics(graph: nx.DiGraph) -> GraphMetrics:
    """Cheap metrics only (Phase 9): PageRank, degrees, SCCs — no betweenness or cycle mining."""
    return compute_graph_metrics(graph, expensive=False, metrics_backend="networkx")


def compute_expensive_graph_metrics(
    graph: nx.DiGraph,
    *,
    metrics_backend: Literal["networkx", "rustworkx"] = "networkx",
) -> GraphMetrics:
    """Full metrics including betweenness, articulation points, and cross-language cycles."""
    return compute_graph_metrics(graph, expensive=True, metrics_backend=metrics_backend)


def _node_language(attrs: dict) -> str:
    for key in ("language", "lang", "source_language"):
        raw = attrs.get(key)
        if raw:
            return str(raw).lower()
    path = str(attrs.get("source_file") or attrs.get("path") or "")
    if path.endswith(".py"):
        return "python"
    if path.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    return ""


def _cross_language_cycles(g: nx.DiGraph) -> list[list[str]]:
    """Simple cycles on the call / invoke subgraph where languages differ on the cycle."""
    h = nx.DiGraph()
    for u, v, data in g.edges(data=True):
        rel = str(data.get("relation") or data.get("label") or "").upper()
        if "CALL" in rel or "HTTP" in rel or "INVOK" in rel or "ROUTE" in rel:
            h.add_edge(u, v)
    if h.number_of_nodes() < 2:
        return []
    out: list[list[str]] = []
    try:
        for cycle in nx.simple_cycles(h):
            if len(cycle) < 2:
                continue
            langs = {_node_language(g.nodes[n]) for n in cycle if n in g} - {""}
            if len(langs) >= 2:
                out.append([str(x) for x in cycle])
            if len(out) >= 50:
                break
    except Exception:  # noqa: BLE001
        return out[:20]
    return out[:20]
