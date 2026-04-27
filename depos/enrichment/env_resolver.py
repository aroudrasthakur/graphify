"""Cross-link code env access to env/config nodes."""
from __future__ import annotations

import re
from pathlib import Path

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


def emit_env_edges(graph: nx.DiGraph, *, repo_root: Path | None = None) -> GraphFragment:
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
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        readers = _candidate_nodes(graph, source_file)
        if not readers:
            continue
        source_id = readers[0]
        for bm in _ENV_BRACKET_DYNAMIC.finditer(text):
            inner = bm.group(1).strip()
            if re.fullmatch(r"['\"][A-Z0-9_]+['\"]", inner):
                continue  # static string — handled by _ENV_REF
            synthetic_id = f"env::dynamic@{path.name}:{bm.start()}"
            if synthetic_id not in seen_nodes and not graph.has_node(synthetic_id):
                seen_nodes.add(synthetic_id)
                new_nodes.append(FragmentNode(
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
                edges.append(FragmentEdge(
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
                    new_nodes.append(FragmentNode(
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
                edges.append(FragmentEdge(
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
    return make_fragment("enrich_env", nodes=new_nodes, edges=edges)


__all__ = ["emit_env_edges"]
