"""Graph sharding helpers for large-monorepo detection passes."""
from __future__ import annotations

from pathlib import Path

import networkx as nx

_MANIFEST_PREFIX = "pkg::manifest:"


def package_manifest_workspace_prefixes(graph: nx.DiGraph) -> list[str]:
    """Directory prefixes (posix, no trailing slash) of every ``package_manifest`` node."""
    prefixes: list[str] = []
    for _, attrs in graph.nodes(data=True):
        if str(attrs.get("node_kind") or "") != "package_manifest":
            continue
        mid = str(attrs.get("manifest_id") or "")
        if not mid.startswith(_MANIFEST_PREFIX):
            continue
        rel = mid[len(_MANIFEST_PREFIX) :]
        try:
            parent = Path(rel).parent.as_posix()
        except ValueError:
            continue
        if parent in {"", "."}:
            prefixes.append("")
        else:
            prefixes.append(parent)
    return sorted(set(prefixes))


def detection_nodes_package_manifest_workspaces(graph: nx.DiGraph) -> frozenset[str] | None:
    """Nodes scoped to on-disk workspaces rooted at dependency manifests.

    Includes every ``package_manifest`` node and any node with a ``source_file``
    path inside one of those workspace directories (prefix match).
    Returns ``None`` when the graph has no package manifests.
    """
    prefixes = package_manifest_workspace_prefixes(graph)
    if not prefixes:
        return None
    members: set[str] = set()
    for nid, attrs in graph.nodes(data=True):
        nk = str(attrs.get("node_kind") or "")
        if nk == "package_manifest":
            members.add(nid)
            continue
        sf = str(attrs.get("source_file") or "").replace("\\", "/")
        if not sf:
            continue
        for p in prefixes:
            if p == "":
                members.add(nid)
                break
            if sf == p or sf.startswith(p + "/"):
                members.add(nid)
                break
    return frozenset(members)


def subgraph_for_shard_strategy(graph: nx.DiGraph, shard_by: str | None) -> nx.DiGraph:
    """Return the graph used for detection / :class:`RunContext` metrics.

    Bundling and snippet extraction should continue to use the original graph.
    """
    if shard_by in (None, "", "none"):
        return graph
    if shard_by == "package_manifest":
        nodes = detection_nodes_package_manifest_workspaces(graph)
        if not nodes:
            return graph
        return graph.subgraph(nodes).copy()
    raise ValueError(f"unknown shard_by strategy: {shard_by!r}")


__all__ = [
    "detection_nodes_package_manifest_workspaces",
    "package_manifest_workspace_prefixes",
    "subgraph_for_shard_strategy",
]
