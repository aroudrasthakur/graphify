"""Cross-link Next.js routes to middleware matchers."""
from __future__ import annotations

import re
from pathlib import Path

import networkx as nx

from depos.analysis.fragments import FragmentEdge, GraphFragment, make_fragment


def _matches(route_path: str, matcher: str) -> bool:
    normalized = matcher.replace(":path*", ".*").replace("*", ".*")
    if normalized in {"/(.*)", ".*"}:
        return True
    try:
        return re.match(f"^{normalized}$", route_path) is not None
    except re.error:
        return route_path.startswith(matcher.rstrip("*"))


def emit_nextjs_edges(graph: nx.DiGraph, *, repo_root: Path | None = None) -> GraphFragment:
    _ = repo_root
    middleware: list[tuple[str, list[str]]] = []
    for node_id, attrs in graph.nodes(data=True):
        if str(attrs.get("node_kind") or "") == "next_middleware":
            middleware.append((node_id, list(attrs.get("matchers") or ["/(.*)"])))
    edges: list[FragmentEdge] = []
    seen: set[tuple[str, str]] = set()
    for route_id, attrs in graph.nodes(data=True):
        if str(attrs.get("node_kind") or "") != "next_route":
            continue
        route_path = str(attrs.get("path") or "/")
        for middleware_id, matchers in middleware:
            if any(_matches(route_path, matcher) for matcher in matchers):
                pair = (middleware_id, route_id)
                if pair not in seen:
                    seen.add(pair)
                    edges.append(FragmentEdge(
                        u=middleware_id,
                        v=route_id,
                        key=None,
                        attrs={
                            "relation": "NEXT_ROUTE_GUARDED_BY_MIDDLEWARE",
                            "source_system": "nextjs",
                            "target_system": "nextjs",
                            "confidence": 0.9,
                            "inferred": True,
                        },
                    ))
    return make_fragment("enrich_nextjs", edges=edges)


__all__ = ["emit_nextjs_edges"]
