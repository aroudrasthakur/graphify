"""CFG + DFG as :class:`GraphFragment` for parallel semantic layers (Phase 8).

Workers build a local :class:`networkx.DiGraph`, then convert to a fragment; the
main thread is the only caller of :func:`~depos.analysis.fragments.merge_fragments`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from depos.analysis.cfg.jsts import build_jsts_function_cfg
from depos.analysis.cfg.python_cfg import build_python_function_cfg
from depos.analysis.dfg.jsts_dfg import build_jsts_dfg
from depos.analysis.dfg.python_dfg import build_python_dfg
from depos.analysis.fragments import (
    FragmentEdge,
    FragmentNode,
    GraphFragment,
    make_fragment,
    merge_fragments,
)

logger = logging.getLogger(__name__)


@dataclass
class CfgDfgScopeWork:
    scope_id: str
    fragment: GraphFragment | None = None
    cfg_error: str | None = None
    dfg_error: str | None = None


def nx_cfg_dfg_subgraph_to_fragment(
    subgraph: nx.DiGraph,
    *,
    scope_id: str,
    source_file: str | None,
    language: str | None,
) -> GraphFragment:
    """Turn a temporary CFG+DFG subgraph into a mergeable :class:`GraphFragment`.

    *file_hash* is set to *scope_id* so :func:`merge_fragments` orders multiple
    scopes from the same source file deterministically (parallel-safe).
    """
    nodes: list[FragmentNode] = []
    for nid in sorted(subgraph.nodes(), key=str):
        attrs = {k: v for k, v in dict(subgraph.nodes[nid]).items()}
        nodes.append(FragmentNode(str(nid), attrs))
    edges: list[FragmentEdge] = []
    for u, v, data in sorted(
        subgraph.edges(data=True), key=lambda t: (str(t[0]), str(t[1]))
    ):
        ed = {k: val for k, val in dict(data).items() if k != "key"}
        edges.append(FragmentEdge(str(u), str(v), None, ed))
    return make_fragment(
        "semantic",
        source_file=source_file,
        file_hash=scope_id,
        language=language,
        nodes=nodes,
        edges=edges,
    )


def compute_python_cfg_dfg_work(
    _graph: nx.DiGraph,
    scope_id: str,
    attrs: dict[str, Any],
    *,
    repo_root: Optional[Path] = None,
) -> CfgDfgScopeWork:
    """Build Python CFG+DFG from source; *_graph* is unused (API matches taint workers)."""
    local = nx.DiGraph()
    cres = build_python_function_cfg(local, scope_id, attrs, repo_root=repo_root)
    if cres.error:
        return CfgDfgScopeWork(scope_id, cfg_error=cres.error)
    dres = build_python_dfg(local, scope_id, attrs, repo_root=repo_root)
    if dres.error:
        return CfgDfgScopeWork(scope_id, dfg_error=dres.error)
    frag = nx_cfg_dfg_subgraph_to_fragment(
        local,
        scope_id=scope_id,
        source_file=str(attrs.get("source_file") or "") or None,
        language="python",
    )
    return CfgDfgScopeWork(scope_id, fragment=frag)


def compute_jsts_cfg_dfg_work(
    _graph: nx.DiGraph,
    scope_id: str,
    attrs: dict[str, Any],
    *,
    repo_root: Optional[Path] = None,
) -> CfgDfgScopeWork:
    """Build JS/TS CFG+DFG from source; *_graph* is unused (API matches taint workers)."""
    local = nx.DiGraph()
    cres = build_jsts_function_cfg(local, scope_id, attrs, repo_root=repo_root)
    if cres.error:
        return CfgDfgScopeWork(scope_id, cfg_error=cres.error)
    dres = build_jsts_dfg(local, scope_id, attrs, repo_root=repo_root)
    if dres.error:
        return CfgDfgScopeWork(scope_id, dfg_error=dres.error)
    lang = str(attrs.get("language") or attrs.get("lang") or "javascript").lower()
    frag = nx_cfg_dfg_subgraph_to_fragment(
        local,
        scope_id=scope_id,
        source_file=str(attrs.get("source_file") or "") or None,
        language=lang if lang else "javascript",
    )
    return CfgDfgScopeWork(scope_id, fragment=frag)


def apply_cfg_dfg_scope_work(graph: nx.DiGraph, work: CfgDfgScopeWork) -> bool:
    """Merge one scope's CFG+DFG fragment into *graph*; returns success."""
    if work.fragment is None:
        return False
    try:
        merge_fragments(graph, [work.fragment])
    except Exception:  # noqa: BLE001
        logger.exception("merge_fragments failed for scope %s", work.scope_id)
        return False
    return True


def cfg_dfg_work_cache_payload(work: CfgDfgScopeWork) -> dict[str, Any]:
    """JSON-serializable cache record for :class:`CfgDfgScopeWork`."""

    payload: dict[str, Any] = {
        "scope_id": work.scope_id,
        "cfg_error": work.cfg_error,
        "dfg_error": work.dfg_error,
        "fragment": None,
    }
    frag = work.fragment
    if frag is not None:
        payload["fragment"] = {
            "stage": frag.stage,
            "source_file": frag.source_file,
            "file_hash": frag.file_hash,
            "language": frag.language,
            "nodes": [{"id": n.node_id, "attrs": dict(n.attrs)} for n in frag.nodes],
            "edges": [
                {"u": e.u, "v": e.v, "key": e.key, "attrs": dict(e.attrs)} for e in frag.edges
            ],
        }
    return payload


def cfg_dfg_work_from_cache_payload(raw: dict[str, Any]) -> CfgDfgScopeWork | None:
    """Restore :class:`CfgDfgScopeWork` from :func:`cfg_dfg_work_cache_payload` output."""

    if not isinstance(raw, dict) or "scope_id" not in raw:
        return None
    scope_id = str(raw["scope_id"])
    cfg_error = raw.get("cfg_error")
    dfg_error = raw.get("dfg_error")
    frag_in = raw.get("fragment")
    if not frag_in:
        return CfgDfgScopeWork(scope_id, cfg_error=cfg_error, dfg_error=dfg_error)
    if not isinstance(frag_in, dict):
        return None
    try:
        nodes = [
            FragmentNode(str(n["id"]), dict(n["attrs"]))  # type: ignore[index]
            for n in frag_in.get("nodes") or []
        ]
        edges = [
            FragmentEdge(
                str(e["u"]),  # type: ignore[index]
                str(e["v"]),  # type: ignore[index]
                e.get("key"),  # type: ignore[arg-type]
                dict(e["attrs"]),  # type: ignore[index]
            )
            for e in frag_in.get("edges") or []
        ]
        frag = make_fragment(
            str(frag_in.get("stage") or "semantic"),
            source_file=frag_in.get("source_file"),
            file_hash=frag_in.get("file_hash"),
            language=frag_in.get("language"),
            nodes=nodes,
            edges=edges,
        )
    except (KeyError, TypeError, ValueError):
        return None
    return CfgDfgScopeWork(scope_id, fragment=frag, cfg_error=cfg_error, dfg_error=dfg_error)


__all__ = [
    "CfgDfgScopeWork",
    "apply_cfg_dfg_scope_work",
    "cfg_dfg_work_cache_payload",
    "cfg_dfg_work_from_cache_payload",
    "compute_jsts_cfg_dfg_work",
    "compute_python_cfg_dfg_work",
    "nx_cfg_dfg_subgraph_to_fragment",
]
