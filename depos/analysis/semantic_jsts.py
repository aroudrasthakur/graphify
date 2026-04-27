"""Phase 1b: JS/TS CFG, DFG, taint; set availability on scope nodes."""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from depos.analysis.semantic_cfg_dfg import (
    CfgDfgScopeWork,
    apply_cfg_dfg_scope_work,
    compute_jsts_cfg_dfg_work,
)
from depos.analysis.taint import (
    TaintScopeWork,
    apply_taint_scope_work,
    compute_jsts_taint_work,
    seam_edge_ids_for_scope,
    taint_for_jsts_scope,
)

logger = logging.getLogger(__name__)

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
    perf = getattr(ctx, "perf", None)
    taint_n = max(1, int(getattr(perf, "taint_n_jobs", 1) or 1)) if perf is not None else 1
    cfg_dfg_n = (
        max(1, int(getattr(perf, "cfg_dfg_n_jobs", 1) or 1)) if perf is not None else 1
    )

    scopes: list[tuple[str, dict[str, Any]]] = []
    for n, attrs in list(graph.nodes(data=True)):
        if not isinstance(attrs, dict):
            continue
        if not _is_jsts_function_node(str(n), attrs):
            continue
        scopes.append((str(n), attrs))

    if not scopes:
        return

    works: dict[str, CfgDfgScopeWork] = {}
    if cfg_dfg_n <= 1 or len(scopes) <= 1:
        for sid, attrs in scopes:
            works[sid] = compute_jsts_cfg_dfg_work(
                graph, sid, attrs, repo_root=repo_root
            )
    else:
        max_w = min(cfg_dfg_n, len(scopes))

        def _cfg_job(sid: str, attrs: dict[str, Any]) -> CfgDfgScopeWork:
            try:
                return compute_jsts_cfg_dfg_work(
                    graph, sid, attrs, repo_root=repo_root
                )
            except Exception:  # noqa: BLE001
                logger.exception("Parallel JS/TS CFG/DFG failed for scope %s", sid)
                return CfgDfgScopeWork(sid, cfg_error="exception")

        with ThreadPoolExecutor(max_workers=max_w) as ex:
            fut_map = {ex.submit(_cfg_job, sid, attrs): sid for sid, attrs in scopes}
            for fut in as_completed(fut_map):
                works[fut_map[fut]] = fut.result()

    taint_tasks: list[tuple[str, dict[str, Any]]] = []
    for sid, attrs in scopes:
        w = works[sid]
        ok = w.fragment is not None
        if ok:
            ok = apply_cfg_dfg_scope_work(graph, w)
        ctx.cfg_available[sid] = ok
        ctx.dfg_available[sid] = ok
        if ok:
            taint_tasks.append((sid, attrs))
        else:
            ctx.taint_edges_available[sid] = False

    if not taint_tasks:
        return

    if taint_n <= 1 or len(taint_tasks) <= 1:
        for sid, attrs in taint_tasks:
            taint_for_jsts_scope(graph, sid, attrs, run_context=ctx, repo_root=repo_root)
            ctx.taint_edges_available[sid] = True
        return

    max_workers = min(taint_n, len(taint_tasks))
    tw: dict[str, Any] = {}

    def _compute(sid: str, attrs: dict[str, Any]) -> Any:
        try:
            return compute_jsts_taint_work(
                graph, sid, attrs, run_context=ctx, repo_root=repo_root
            )
        except Exception:  # noqa: BLE001
            logger.exception("Parallel JS/TS taint compute failed for scope %s", sid)
            return TaintScopeWork(sid, seam_edge_ids_for_scope(graph, sid))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {
            ex.submit(_compute, sid, attrs): sid for sid, attrs in taint_tasks
        }
        for fut in as_completed(future_map):
            sid = future_map[fut]
            tw[sid] = fut.result()

    for sid, attrs in taint_tasks:
        apply_taint_scope_work(graph, tw[sid])
        ctx.taint_edges_available[sid] = True
