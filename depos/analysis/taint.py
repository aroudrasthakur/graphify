"""Pre-compute taint metadata (``TAINT``) from Python function bodies. JS/TS: Phase 1b."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from depos.analysis.cfg import python_cfg as _cfg
from depos.analysis.run_context import RunContext
from depos.analysis.schemas import SeamEdge, SemanticEdgeMetadata, TaintEdge
from depos.analysis.seams import SeamEdge as SeamsDTE

_TAINT_SINKS = re.compile(
    r"(execute\(\s*|\.execute\(\s*|raw\(|os\.system|subprocess|eval\(|eval\s*\(|exec\()",
    re.I,
)


def _annotate_scope_seam_edge_ids(graph: nx.DiGraph, scope_id: str, attrs: dict[str, Any]) -> None:
    """Set ``seam_edge_ids`` on the scope node from incident seam edges' ``edge_id`` attributes."""
    ids: list[str] = []
    seen: set[str] = set()
    for u, v, data in graph.edges(data=True):
        if u != scope_id and v != scope_id:
            continue
        is_seam = bool(data.get("seam")) or (
            data.get("source_system") and data.get("target_system")
        )
        if not is_seam:
            continue
        eid = str(data.get("edge_id") or f"{u}->{v}")
        if eid not in seen:
            seen.add(eid)
            ids.append(eid)
    attrs["seam_edge_ids"] = ids


def _find_edge_by_eid(
    graph: nx.DiGraph, eid: str
) -> Optional[tuple[str, str, dict[str, Any]]]:
    for u, v, data in graph.edges(data=True):
        cur = str(data.get("edge_id") or f"{u}->{v}")
        if cur == eid:
            return u, v, data
    return None


def _seam_schemas_for_ids(
    graph: nx.DiGraph, edge_ids: list[str], seam_edge_index: dict[str, Any]
) -> list[SeamEdge]:
    out: list[SeamEdge] = []
    for eid in edge_ids:
        rec: Any = seam_edge_index.get(eid)
        if isinstance(rec, SeamsDTE):
            out.append(
                SeamEdge(
                    edge_id=rec.edge_id,
                    source=rec.u,
                    target=rec.v,
                    relation=rec.relation,
                    metadata=SemanticEdgeMetadata(),
                )
            )
            continue
        found = _find_edge_by_eid(graph, eid)
        if not found:
            continue
        u, v, data = found
        rel = str(data.get("relation") or data.get("label") or "edge")
        try:
            metadata = SemanticEdgeMetadata.model_validate(
                {k2: v2 for k2, v2 in data.items() if k2 != "relation"}
            )
        except Exception:  # noqa: BLE001
            metadata = SemanticEdgeMetadata()
        out.append(
            SeamEdge(
                edge_id=eid,
                source=u,
                target=v,
                relation=rel,
                metadata=metadata,
            )
        )
    return out


def _append_taint_graph_outputs(
    graph: nx.DiGraph,
    typed: list[TaintEdge],
    *,
    row_extras: list[dict[str, Any] | None] | None = None,
) -> list[dict[str, Any]]:
    """Write ``taint_edges`` (typed :class:`TaintEdge` list)."""
    if not typed:
        return []
    graph.graph.setdefault("taint_edges", []).extend(typed)
    out_rows: list[dict[str, Any]] = []
    for i, te in enumerate(typed):
        d = te.model_dump(mode="json")
        d["type"] = "TAINT"
        extra = (row_extras or [None] * len(typed))[i]
        if extra:
            d.update(extra)
        out_rows.append(d)
    return out_rows


def taint_for_python_scope(
    graph: nx.DiGraph,
    scope_id: str,
    attrs: dict[str, Any],
    *,
    run_context: RunContext,
    repo_root: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """When a taint sink appears in a function body, add a graph edge and return rows.

    Emits :class:`TaintEdge` into ``graph.graph["taint_edges"]``.
    """
    _annotate_scope_seam_edge_ids(graph, scope_id, attrs)
    seam_index = run_context.seam_edge_index
    out_typed: list[TaintEdge] = []

    rel = str(attrs.get("source_file") or "")
    start = int(
        (attrs.get("span") or {}).get("start", {}).get("line")
        or attrs.get("start_line")
        or attrs.get("lineno")
        or 0
    )
    if not rel or not start:
        return []
    qn = str(attrs.get("qualname") or attrs.get("name") or "")
    source_hints: list[str] = [h for h in (qn, rel) if h]
    src = _cfg._read_source(repo_root, rel)  # noqa: SLF001
    if not src:
        return []
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError:
        return []
    if not isinstance(tree, ast.Module):
        return []
    fn = _cfg._find_function(  # noqa: SLF001
        tree, qualname=qn, start_line=start, end_line=int(attrs.get("end_line") or start)
    ) or _cfg._fallback_by_line(  # noqa: SLF001
        tree, start, int(attrs.get("end_line") or start + 500)
    )
    if not fn or not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []

    eids: list[str] = list(attrs.get("seam_edge_ids", []) or [])
    seam_list = _seam_schemas_for_ids(graph, eids, seam_index)
    has_http = bool(attrs.get("http_call_sites"))
    for node in fn.body:
        chunk = ast.get_source_segment(src, node) or ""
        m = _TAINT_SINKS.search(chunk)
        if not m:
            continue
        line = int(getattr(node, "lineno", 0) or 0)
        u, v = f"taint:src:{scope_id}", f"taint:sink:{scope_id}:L{line}"
        if u not in graph:
            graph.add_node(u, type="taint_endpoint", label="taint_source")
        if v not in graph:
            graph.add_node(v, type="taint_endpoint", label="taint_sink")
        te = TaintEdge(
            source_node=u,
            sink_node=v,
            intermediate_path=[u, v],  # TODO: inter-procedural tracing
            crosses_seam=has_http or bool(seam_list),
            seam_edges_crossed=seam_list,
            source_chain=f"{rel}:{line}",
            sink_pattern=m.group(0).strip()[:64],
            source_hints=source_hints,
            scope=scope_id,
            line=line,
        )
        out_typed.append(te)
        graph.add_edge(
            u,
            v,
            type="TAINT",
            taint_line=line,
            sink_pattern=te.sink_pattern,
            path=f"{rel}:{line}",
        )
    if not out_typed:
        return []
    return _append_taint_graph_outputs(graph, out_typed)


_JSTS_TAINT_SINKS = re.compile(
    r"(eval\s*\(|innerHTML|child_process|\.exec\(\s*|execute\(\s*|`select\s)",
    re.I,
)
_JSTS_TAINT_SRC = re.compile(
    r"req\.(query|body|params|cookies|headers)|document\.location|location\.search|getParameter\s*\(",
    re.I,
)


def taint_for_jsts_scope(
    graph: nx.DiGraph,
    scope_id: str,
    attrs: dict[str, Any],
    *,
    run_context: RunContext,
    repo_root: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """Heuristic taint for JS/TS: known sources + known sinks in function text (Phase 1b)."""
    from tree_sitter import Parser

    from depos.analysis.cfg.jsts import (
        _find_innermost_function,
        _get_function_body,
        _load_language_for_path,
        read_source_bytes,
    )

    _annotate_scope_seam_edge_ids(graph, scope_id, attrs)
    seam_index = run_context.seam_edge_index
    eids: list[str] = list(attrs.get("seam_edge_ids", []) or [])
    seam_list = _seam_schemas_for_ids(graph, eids, seam_index)
    has_http = bool(attrs.get("http_call_sites"))

    out_typed: list[TaintEdge] = []
    rel = str(attrs.get("source_file") or "")
    start = int(
        (attrs.get("span") or {}).get("start", {}).get("line")
        or attrs.get("start_line")
        or attrs.get("lineno")
        or 0
    )
    if not rel or not start:
        return []
    raw = read_source_bytes(repo_root, rel)
    if not raw:
        return []
    try:
        lang = _load_language_for_path(rel)
        tree = Parser(lang).parse(raw)
    except Exception:  # noqa: BLE001
        return []
    fn = _find_innermost_function(tree.root_node, start)
    if fn is None:
        return []
    body = _get_function_body(fn)
    if body is None:
        return []
    text = raw[int(body.start_byte) : int(body.end_byte)].decode("utf-8", errors="replace")
    sink_m = _JSTS_TAINT_SINKS.search(text)
    js_sources = [x.group(0) for x in _JSTS_TAINT_SRC.finditer(text)]
    if not sink_m and not js_sources:
        return []
    line = int(body.start_point[0]) + 1
    u, v = f"taint:src:{scope_id}", f"taint:sink:{scope_id}:L{line}"
    if u not in graph:
        graph.add_node(u, type="taint_endpoint", label="taint_source")
    if v not in graph:
        graph.add_node(v, type="taint_endpoint", label="taint_sink")
    te = TaintEdge(
        source_node=u,
        sink_node=v,
        intermediate_path=[u, v],  # TODO: inter-procedural tracing
        crosses_seam=has_http or bool(seam_list),
        seam_edges_crossed=seam_list,
        source_chain=f"{rel}:{line}",
        sink_pattern=(sink_m.group(0).strip()[:64] if sink_m else "source_only"),
        source_hints=list(js_sources),
        scope=scope_id,
        line=line,
    )
    out_typed.append(te)
    graph.add_edge(
        u, v, type="TAINT", taint_line=line, sink_pattern=te.sink_pattern, path=f"{rel}:{line}"
    )
    return _append_taint_graph_outputs(
        graph, out_typed, row_extras=[{"js_sources": js_sources}]
    )
