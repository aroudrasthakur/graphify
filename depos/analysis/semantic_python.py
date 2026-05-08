"""Phase 1a: Python CFG, DFG, taint; set availability on scope nodes."""
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
)
from depos.analysis.taint import (
    TaintScopeWork,
    apply_taint_scope_work,
    seam_edge_ids_for_scope,
)

logger = logging.getLogger(__name__)

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


def _python_scope_source_hash(repo_root: Optional[Path], attrs: dict[str, Any]) -> str:
    rel = str(attrs.get("source_file") or "")
    if repo_root and rel:
        try:
            path = (repo_root / rel).resolve()
            if path.is_file():
                from depos.cache import file_content_hash

                return file_content_hash(path)
        except OSError:
            pass
    from depos.cache import stable_hash

    span = attrs.get("span")
    start = (span or {}).get("start", {}).get("line") if isinstance(span, dict) else None
    return stable_hash(
        {
            "rel": rel,
            "start": start,
            "qn": attrs.get("qualname") or attrs.get("name"),
        }
    )


def _cfg_dfg_work_with_cache(
    graph: nx.DiGraph,
    sid: str,
    attrs: dict[str, Any],
    *,
    repo_root: Optional[Path],
    fragment_cache: Any,
) -> CfgDfgScopeWork:
    from depos.cache import build_semantic_function_cache_key

    from depos.analysis.semantic_cfg_dfg import (
        cfg_dfg_work_cache_payload,
        cfg_dfg_work_from_cache_payload,
        compute_python_cfg_dfg_work,
    )

    rel = str(attrs.get("source_file") or "")
    fh = _python_scope_source_hash(repo_root, attrs)
    key = build_semantic_function_cache_key(
        function_id=sid,
        source_file=rel or sid,
        function_source_hash=fh,
        language="python",
        version_tuple=("cfg-dfg-v1",),
    )
    if fragment_cache is not None:
        hit = fragment_cache.get(key)
        if hit is not None and isinstance(hit, dict):
            restored = cfg_dfg_work_from_cache_payload(hit)
            if restored is not None:
                return restored
    work = compute_python_cfg_dfg_work(graph, sid, attrs, repo_root=repo_root)
    if fragment_cache is not None and work.cfg_error != "exception":
        fragment_cache.put(key, cfg_dfg_work_cache_payload(work))
    return work


def _python_taint_work_with_cache(
    graph: nx.DiGraph,
    sid: str,
    attrs: dict[str, Any],
    ctx: Any,
    *,
    repo_root: Optional[Path],
    fragment_cache: Any,
) -> TaintScopeWork:
    from depos.cache import build_semantic_function_cache_key

    from depos.analysis.taint import (
        compute_python_taint_work,
        taint_graph_fingerprint,
        taint_work_cache_payload,
        taint_work_from_cache_payload,
    )

    rel = str(attrs.get("source_file") or "")
    fh = _python_scope_source_hash(repo_root, attrs)
    fp = taint_graph_fingerprint(graph, sid)
    key = build_semantic_function_cache_key(
        function_id=sid,
        source_file=rel or sid,
        function_source_hash=fh,
        language="python",
        version_tuple=("taint-v1", fp),
    )
    if fragment_cache is not None:
        hit = fragment_cache.get(key)
        if hit is not None and isinstance(hit, dict):
            restored = taint_work_from_cache_payload(hit)
            if restored is not None:
                return restored
    work = compute_python_taint_work(graph, sid, attrs, run_context=ctx, repo_root=repo_root)
    if fragment_cache is not None:
        fragment_cache.put(key, taint_work_cache_payload(work))
    return work


def enrich_python_semantics(
    graph: nx.DiGraph,
    ctx: Any,
    *,
    repo_root: Optional[Path] = None,
    fragment_cache: Any = None,
) -> None:
    """Build CFG+DFG+taint for Python function-like nodes; set flags on ``ctx``."""
    perf = getattr(ctx, "perf", None)
    taint_n = max(1, int(getattr(perf, "taint_n_jobs", 1) or 1)) if perf is not None else 1
    cfg_dfg_n = (
        max(1, int(getattr(perf, "cfg_dfg_n_jobs", 1) or 1)) if perf is not None else 1
    )

    scopes: list[tuple[str, dict[str, Any]]] = []
    for n, attrs in list(graph.nodes(data=True)):
        if not isinstance(attrs, dict):
            continue
        if not _is_python_function_node(str(n), attrs):
            continue
        scopes.append((str(n), attrs))

    if not scopes:
        return

    works: dict[str, CfgDfgScopeWork] = {}
    if cfg_dfg_n <= 1 or len(scopes) <= 1:
        for sid, attrs in scopes:
            works[sid] = _cfg_dfg_work_with_cache(
                graph, sid, attrs, repo_root=repo_root, fragment_cache=fragment_cache
            )
    else:
        max_w = min(cfg_dfg_n, len(scopes))

        def _cfg_job(sid: str, attrs: dict[str, Any]) -> CfgDfgScopeWork:
            try:
                return _cfg_dfg_work_with_cache(
                    graph, sid, attrs, repo_root=repo_root, fragment_cache=fragment_cache
                )
            except Exception:  # noqa: BLE001
                logger.exception("Parallel Python CFG/DFG failed for scope %s", sid)
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
            tw = _python_taint_work_with_cache(
                graph, sid, attrs, ctx, repo_root=repo_root, fragment_cache=fragment_cache
            )
            apply_taint_scope_work(graph, tw)
            ctx.taint_edges_available[sid] = True
        return

    max_workers = min(taint_n, len(taint_tasks))
    tw: dict[str, Any] = {}

    def _compute(sid: str, attrs: dict[str, Any]) -> Any:
        try:
            return _python_taint_work_with_cache(
                graph, sid, attrs, ctx, repo_root=repo_root, fragment_cache=fragment_cache
            )
        except Exception:  # noqa: BLE001
            logger.exception("Parallel taint compute failed for scope %s", sid)
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
