"""Phase 1b: JS/TS CFG, DFG, taint; set availability on scope nodes."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from depos.analysis.cfg.jsts import build_jsts_function_cfg
from depos.analysis.dfg.jsts_dfg import build_jsts_dfg
from depos.analysis.taint import taint_for_jsts_scope

_TS_JS = re.compile(r"\.(mjs|cjs|js|jsx|ts|tsx|mts|cts)$", re.I)
_ENTITY = re.compile(
    r"function_declaration|function\b|method_definition|arrow_function",
    re.I,
)


def _is_jsts_function_node(_node: str, attrs: dict) -> bool:
    lang = str(attrs.get("language") or attrs.get("lang") or "").lower()
    if lang not in ("javascript", "typescript", "js", "ts", "tsx", "jsx"):
        p = str(attrs.get("source_file") or "")
        if not _TS_JS.search(p):
            return False
    else:
        p = str(attrs.get("source_file") or "")
        if p and not _TS_JS.search(p):
            return False
    kind = str(
        attrs.get("entity_kind")
        or attrs.get("ast_kind")
        or attrs.get("node_kind")
        or attrs.get("kind")
        or ""
    )
    if _ENTITY.search(kind):
        return True
    lab = str(attrs.get("label") or attrs.get("name") or "")
    if "function" in kind.lower() or "=>" in lab or "(" in lab:
        return True
    return False


def enrich_jsts_semantics(
    graph: nx.DiGraph,
    ctx: Any,
    *,
    repo_root: Optional[Path] = None,
) -> None:
    """Build CFG+DFG+taint for JS/TS function-like nodes; set flags on ``ctx``."""
    for n, attrs in list(graph.nodes(data=True)):
        if not isinstance(attrs, dict):
            continue
        if not _is_jsts_function_node(str(n), attrs):
            continue
        sid = str(n)
        cres = build_jsts_function_cfg(graph, sid, attrs, repo_root=repo_root)
        dres = build_jsts_dfg(graph, sid, attrs, repo_root=repo_root)
        ok = not cres.error and not dres.error
        ctx.cfg_available[sid] = ok
        ctx.dfg_available[sid] = ok
        if ok:
            taint_for_jsts_scope(graph, sid, attrs, run_context=ctx, repo_root=repo_root)
            ctx.taint_edges_available[sid] = True
        else:
            ctx.taint_edges_available[sid] = False
