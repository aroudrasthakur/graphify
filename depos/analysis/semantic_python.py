"""Phase 1a: Python CFG, DFG, taint; set availability on scope nodes."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from depos.analysis.cfg.python_cfg import build_python_function_cfg
from depos.analysis.dfg.python_dfg import build_python_dfg
from depos.analysis.taint import taint_for_python_scope

_FUNC_LABEL = re.compile(
    r"^(?:async\s+)?def\s+\w+|\w+\s*\(|\)\s*->\s*",
    re.M,
)
_PY_ENTITY = re.compile(
    r"function_definition|function_declaration|method_definition|def\b",
    re.I,
)


def _is_python_function_node(node: str, attrs: dict) -> bool:
    if attrs.get("language") and str(attrs["language"]).lower() != "python":
        return False
    p = str(attrs.get("source_file") or "")
    if p and not p.endswith(".py"):
        if str(attrs.get("language") or "").lower() not in ("python", "py"):
            return False
    kind = str(
        attrs.get("entity_kind")
        or attrs.get("ast_kind")
        or attrs.get("node_kind")
        or attrs.get("kind")
        or ""
    )
    if _PY_ENTITY.search(kind):
        return True
    lab = str(attrs.get("label") or attrs.get("name") or "")
    if _FUNC_LABEL.search(lab):
        return True
    if attrs.get("is_fastapi_route") and p.endswith(".py"):
        return True
    if "def " in lab.lower() or "()" in lab:
        if p.endswith(".py"):
            return True
    return False


def enrich_python_semantics(
    graph: nx.DiGraph,
    ctx: Any,
    *,
    repo_root: Optional[Path] = None,
) -> None:
    """Build CFG+DFG+taint for Python function-like nodes; set flags on ``ctx``."""
    for n, attrs in list(graph.nodes(data=True)):
        if not isinstance(attrs, dict):
            continue
        if not _is_python_function_node(str(n), attrs):
            continue
        sid = str(n)
        cres = build_python_function_cfg(graph, sid, attrs, repo_root=repo_root)
        dres = build_python_dfg(graph, sid, attrs, repo_root=repo_root)
        ok = not cres.error and not dres.error
        ctx.cfg_available[sid] = ok
        ctx.dfg_available[sid] = ok
        if ok:
            taint_for_python_scope(graph, sid, attrs, run_context=ctx, repo_root=repo_root)
            # Layer ran successfully (may still emit zero TAINT edges)
            ctx.taint_edges_available[sid] = True
        else:
            ctx.taint_edges_available[sid] = False
