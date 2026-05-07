"""Cross-link code env access to env/config nodes."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import networkx as nx

from depos.analysis.fragments import FragmentEdge, FragmentNode, GraphFragment, make_fragment

_ENV_REF = re.compile(r"(?:process\.env\.|process\.env\[['\"]|os\.getenv\(['\"]|os\.environ(?:\.get)?\(['\"])([A-Z0-9_]+)")
# Dynamic / non-literal bracket access: process.env[foo] or process.env['x' + y]
_ENV_BRACKET_DYNAMIC = re.compile(r"process\.env\[([^\]]+)\]")


def _candidate_nodes(graph: nx.DiGraph, source_file: str) -> list[str]:
    out = [
        node_id
        for node_id, attrs in graph.nodes(data=True)
        if str(attrs.get("source_file") or "") == source_file and str(attrs.get("node_kind") or "") not in {"env_var", "config_key"}
    ]
    return out[:1]


def _edges_from_cached(hit: dict[str, Any]) -> tuple[list[FragmentNode], list[FragmentEdge]]:
    nodes = [FragmentNode(n["node_id"], dict(n["attrs"])) for n in hit.get("nodes", [])]
    edges = [
        FragmentEdge(e["u"], e["v"], e.get("key"), dict(e["attrs"]))
        for e in hit.get("edges", [])
    ]
    return nodes, edges


def _serialize_fragment(
    nodes: list[FragmentNode], edges: list[FragmentEdge]
) -> dict[str, Any]:
    return {
        "nodes": [{"node_id": n.node_id, "attrs": dict(n.attrs)} for n in nodes],
        "edges": [
            {"u": e.u, "v": e.v, "key": e.key, "attrs": dict(e.attrs)}
            for e in edges
        ],
    }


def emit_env_edges(
    graph: nx.DiGraph,
    *,
    repo_root: Path | None = None,
    fragment_cache: Any | None = None,
) -> GraphFragment:
    if repo_root is None:
        return make_fragment("enrich_env")
    env_nodes: dict[str, list[str]] = {}
    for node_id, attrs in graph.nodes(data=True):
        if str(attrs.get("node_kind") or "") == "env_var":
            env_nodes.setdefault(str(attrs.get("name") or ""), []).append(node_id)
    new_nodes: list[FragmentNode] = []
    edges: list[FragmentEdge] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()
    seen_files: set[str] = set()
    for _, attrs in graph.nodes(data=True):
        source_file = str(attrs.get("source_file") or "")
        if not source_file or source_file in seen_files:
            continue
        seen_files.add(source_file)
        path = Path(source_file)
        if not path.exists() or path.is_dir():
            continue

        cache_hit: dict[str, Any] | None = None
        if fragment_cache is not None:
            try:
                from depos.cache import build_enrichment_fragment_cache_key, file_content_hash

                file_hash = file_content_hash(path)
                key = build_enrichment_fragment_cache_key(
                    stage="emit_env_edges",
                    source_file=path.as_posix(),
                    file_hash=file_hash,
                    language="generic",
                    enricher_logic_version="env-v1",
                )
                raw = fragment_cache.get(key)
                if isinstance(raw, dict) and "nodes" in raw and "edges" in raw:
                    cache_hit = raw
            except Exception:
                cache_hit = None

        if cache_hit is not None:
            fnodes, fedges = _edges_from_cached(cache_hit)
            for n in fnodes:
                if n.node_id in seen_nodes or graph.has_node(n.node_id):
                    continue
                seen_nodes.add(n.node_id)
                new_nodes.append(n)
            for e in fedges:
                pair = (e.u, e.v)
                if pair in seen_edges or graph.has_edge(e.u, e.v):
                    continue
                seen_edges.add(pair)
                edges.append(e)
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        readers = _candidate_nodes(graph, source_file)
        if not readers:
            continue
        source_id = readers[0]
        file_nodes: list[FragmentNode] = []
        file_edges: list[FragmentEdge] = []
        for bm in _ENV_BRACKET_DYNAMIC.finditer(text):
            inner = bm.group(1).strip()
            if re.fullmatch(r"['\"][A-Z0-9_]+['\"]", inner):
                continue  # static string — handled by _ENV_REF
            synthetic_id = f"env::dynamic@{path.name}:{bm.start()}"
            if synthetic_id not in seen_nodes and not graph.has_node(synthetic_id):
                seen_nodes.add(synthetic_id)
                file_nodes.append(FragmentNode(
                    node_id=synthetic_id,
                    attrs={
                        "node_kind": "env_var",
                        "universe": "env",
                        "source_file": source_file,
                        "label": "dynamic",
                        "dynamic": True,
                    },
                ))
            pair = (source_id, synthetic_id)
            if pair not in seen_edges and not graph.has_edge(source_id, synthetic_id):
                seen_edges.add(pair)
                file_edges.append(FragmentEdge(
                    u=source_id,
                    v=synthetic_id,
                    key=None,
                    attrs={
                        "relation": "READS_ENV_VAR",
                        "source_system": "code",
                        "target_system": "env",
                        "confidence": 0.45,
                        "inferred": False,
                    },
                ))
        for match in _ENV_REF.finditer(text):
            name = match.group(1)
            targets = env_nodes.get(name, [])
            if not targets:
                synthetic_id = f"env::{name}@{path.name}"
                if synthetic_id not in seen_nodes and not graph.has_node(synthetic_id):
                    seen_nodes.add(synthetic_id)
                    file_nodes.append(FragmentNode(
                        node_id=synthetic_id,
                        attrs={
                            "node_kind": "env_var",
                            "universe": "env",
                            "source_file": source_file,
                            "name": name,
                            "label": name,
                            "defined": False,
                        },
                    ))
                    env_nodes.setdefault(name, []).append(synthetic_id)
                targets = env_nodes.get(name, [synthetic_id])
            for target_id in targets:
                pair = (source_id, target_id)
                if pair in seen_edges or graph.has_edge(source_id, target_id):
                    continue
                seen_edges.add(pair)
                target_attrs = graph.nodes[target_id] if graph.has_node(target_id) else {}
                confidence = (
                    1.0 if target_attrs.get("defined") and not target_attrs.get("typed_drift")
                    else 0.8 if target_attrs.get("defined")
                    else 0.5
                )
                file_edges.append(FragmentEdge(
                    u=source_id,
                    v=target_id,
                    key=None,
                    attrs={
                        "relation": "READS_ENV_VAR",
                        "source_system": "code",
                        "target_system": "env",
                        "confidence": confidence,
                        "inferred": False,
                    },
                ))

        if fragment_cache is not None and file_nodes:
            try:
                from depos.cache import build_enrichment_fragment_cache_key, file_content_hash

                file_hash = file_content_hash(path)
                key = build_enrichment_fragment_cache_key(
                    stage="emit_env_edges",
                    source_file=path.as_posix(),
                    file_hash=file_hash,
                    language="generic",
                    enricher_logic_version="env-v1",
                )
                fragment_cache.put(key, _serialize_fragment(file_nodes, file_edges))
            except Exception:
                pass

        new_nodes.extend(file_nodes)
        edges.extend(file_edges)
    return make_fragment("enrich_env", nodes=new_nodes, edges=edges)


__all__ = ["emit_env_edges"]
