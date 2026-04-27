"""O(1) lookup indexes over the canonical graph (Phase 7).

Built after Module 1 enrichment and semantic passes in ``build_run_context``.
Dict values are mutable; treat as read-only after construction.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx

from depos.graph_relations import HTTP_CALLS_ROUTE


@dataclass(frozen=True, slots=True)
class GraphIndexes:
    node_by_id: dict[str, dict[str, Any]]
    nodes_by_type: dict[str, list[str]]
    nodes_by_file: dict[str, list[str]]
    functions_by_file: dict[str, list[str]]
    symbols_by_name: dict[str, list[str]]
    routes_by_path: dict[tuple[str, str], list[str]]
    env_vars_by_name: dict[str, list[str]]
    packages_by_name: dict[str, list[str]]
    diagnostics_by_node: dict[str, list[dict]]
    callers_by_callee: dict[str, list[str]]
    callees_by_caller: dict[str, list[str]]
    seams_by_node: dict[str, list[str]]
    taint_edges_by_source: dict[str, list[int]]
    taint_edges_by_sink: dict[str, list[int]]


def _norm_path(p: str) -> str:
    return str(Path(p).as_posix()).lstrip("./")


def _is_call_edge(data: dict[str, Any]) -> bool:
    return str(data.get("relation") or data.get("type") or "").casefold() == "calls"


def _function_like(attrs: dict[str, Any]) -> bool:
    kind = str(
        attrs.get("entity_kind")
        or attrs.get("ast_kind")
        or attrs.get("node_kind")
        or attrs.get("kind")
        or ""
    ).lower()
    if "function" in kind or "method" in kind:
        return True
    if attrs.get("qualname") or attrs.get("is_fastapi_route"):
        return True
    lab = str(attrs.get("label") or attrs.get("name") or "")
    return "def " in lab.lower() or "=>" in lab


def build_graph_indexes(graph: nx.DiGraph) -> GraphIndexes:
    """Single pass over nodes and edges; deterministic ordering in list values."""
    node_by_id: dict[str, dict[str, Any]] = {}
    nodes_by_type: dict[str, list[str]] = {}
    nodes_by_file: dict[str, list[str]] = {}
    functions_by_file: dict[str, list[str]] = {}
    symbols_by_name: dict[str, list[str]] = {}
    routes_by_path: dict[tuple[str, str], list[str]] = {}
    env_vars_by_name: dict[str, list[str]] = {}
    packages_by_name: dict[str, list[str]] = {}
    diagnostics_by_node: dict[str, list[dict]] = {}
    callers_by_callee: dict[str, list[str]] = {}
    callees_by_caller: dict[str, list[str]] = {}
    seams_by_node: dict[str, list[str]] = {}
    taint_edges_by_source: dict[str, list[int]] = {}
    taint_edges_by_sink: dict[str, list[int]] = {}

    for nid in sorted(graph.nodes(), key=str):
        attrs = dict(graph.nodes[nid])
        node_by_id[str(nid)] = attrs
        nid_s = str(nid)

        ntype = str(attrs.get("type") or attrs.get("entity_kind") or attrs.get("node_kind") or "")
        if ntype:
            nodes_by_type.setdefault(ntype, []).append(nid_s)

        sf = attrs.get("source_file") or ""
        if sf:
            key = _norm_path(str(sf))
            nodes_by_file.setdefault(key, []).append(nid_s)
            if _function_like(attrs):
                functions_by_file.setdefault(key, []).append(nid_s)

        for name_key in ("name", "qualname", "label"):
            raw = attrs.get(name_key)
            if raw and isinstance(raw, str) and len(raw) < 256:
                symbols_by_name.setdefault(raw, []).append(nid_s)

        if attrs.get("is_fastapi_route"):
            method = (attrs.get("http_method") or "GET").upper()
            path = str(attrs.get("route_pattern") or "")
            routes_by_path.setdefault((method, path), []).append(nid_s)

        ev = attrs.get("env_var_name") or attrs.get("env_name")
        if ev:
            env_vars_by_name.setdefault(str(ev), []).append(nid_s)

        pkg = attrs.get("package_name") or attrs.get("npm_package")
        if pkg:
            packages_by_name.setdefault(str(pkg), []).append(nid_s)

    for k, lst in nodes_by_file.items():
        nodes_by_file[k] = sorted(lst)
    for k, lst in functions_by_file.items():
        functions_by_file[k] = sorted(lst)
    for k, lst in nodes_by_type.items():
        nodes_by_type[k] = sorted(lst)
    for k, lst in symbols_by_name.items():
        symbols_by_name[k] = sorted(set(lst))
    for k, lst in routes_by_path.items():
        routes_by_path[k] = sorted(lst)
    for k, lst in env_vars_by_name.items():
        env_vars_by_name[k] = sorted(lst)
    for k, lst in packages_by_name.items():
        packages_by_name[k] = sorted(lst)

    for u, v, data in graph.edges(data=True):
        u_s, v_s = str(u), str(v)
        if _is_call_edge(data):
            callers_by_callee.setdefault(v_s, []).append(u_s)
            callees_by_caller.setdefault(u_s, []).append(v_s)
        is_seam = bool(data.get("seam")) or (
            data.get("source_system") and data.get("target_system")
        )
        if is_seam:
            eid = str(data.get("edge_id") or f"{u_s}->{v_s}")
            seams_by_node.setdefault(u_s, []).append(eid)
            seams_by_node.setdefault(v_s, []).append(eid)
        if data.get("relation") == HTTP_CALLS_ROUTE:
            eid = str(data.get("edge_id") or f"{u_s}->{v_s}")
            seams_by_node.setdefault(u_s, []).append(eid)
            seams_by_node.setdefault(v_s, []).append(eid)

    for k, lst in callers_by_callee.items():
        callers_by_callee[k] = sorted(set(lst))
    for k, lst in callees_by_caller.items():
        callees_by_caller[k] = sorted(set(lst))
    for k, lst in seams_by_node.items():
        seams_by_node[k] = sorted(set(lst))

    taint_list = graph.graph.get("taint_edges") or []
    for i, te in enumerate(taint_list):
        src = getattr(te, "source_node", None) or (
            te.get("source_node") if isinstance(te, dict) else None
        )
        snk = getattr(te, "sink_node", None) or (
            te.get("sink_node") if isinstance(te, dict) else None
        )
        if src:
            taint_edges_by_source.setdefault(str(src), []).append(i)
        if snk:
            taint_edges_by_sink.setdefault(str(snk), []).append(i)

    return GraphIndexes(
        node_by_id=node_by_id,
        nodes_by_type=nodes_by_type,
        nodes_by_file=nodes_by_file,
        functions_by_file=functions_by_file,
        symbols_by_name=symbols_by_name,
        routes_by_path=routes_by_path,
        env_vars_by_name=env_vars_by_name,
        packages_by_name=packages_by_name,
        diagnostics_by_node=diagnostics_by_node,
        callers_by_callee=callers_by_callee,
        callees_by_caller=callees_by_caller,
        seams_by_node=seams_by_node,
        taint_edges_by_source=taint_edges_by_source,
        taint_edges_by_sink=taint_edges_by_sink,
    )


__all__ = ["GraphIndexes", "build_graph_indexes"]
