"""One-shot graph metrics for :class:`RunContext` (Section 5.1)."""
from __future__ import annotations

import networkx as nx

from depos.analysis.run_context import GraphMetrics


def compute_graph_metrics(graph: nx.DiGraph) -> GraphMetrics:
    """PageRank, betweenness (sampled on large graphs), fan-in/out, SCCs, cross-lang cycles."""
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

    if n <= 400:
        betw = nx.betweenness_centrality(g, normalized=True)
    else:
        k = min(200, n)
        betw = nx.betweenness_centrality(g, k=k, normalized=True, seed=42)

    fin: dict[str, int] = {}
    fout: dict[str, int] = {}
    for node in g.nodes():
        ns = str(node)
        fin[ns] = g.in_degree(node)
        fout[ns] = g.out_degree(node)

    scc = list(nx.strongly_connected_components(g))
    scc_id: dict[str, int] = {}
    for i, comp in enumerate(scc):
        for node in comp:
            scc_id[str(node)] = i

    cycles: list[list[str]] = _cross_language_cycles(g)

    metrics = GraphMetrics(
        node_pagerank={str(k): float(v) for k, v in pr.items()},
        betweenness={str(k): float(v) for k, v in betw.items()},
        fan_in=fin,
        fan_out=fout,
        scc_count=len(scc),
        scc_id_by_node=scc_id,
        cross_lang_cycles=cycles,
    )
    metrics._computed = True
    return metrics


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
            langs = {
                _node_language(g.nodes[n]) for n in cycle if n in g
            } - {""}
            if len(langs) >= 2:
                out.append([str(x) for x in cycle])
            if len(out) >= 50:
                break
    except Exception:  # noqa: BLE001
        return out[:20]
    return out[:20]
