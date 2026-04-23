"""Simplified DFG: name def edges for taint; def-use for locals inside Python function bodies."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import networkx as nx

from depos.analysis.cfg import python_cfg as _cfg


@dataclass
class DfgResult:
    dfg_edges: list[tuple[str, str, str]] = field(default_factory=list)  # (def_site, use_site, var)
    error: Optional[str] = None


def _names_in(expr: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)}


def _build_last_def(
    body: list[ast.stmt],
    last: dict[str, str],
    prefix: str,
) -> None:
    for st in body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(st, ast.Assign):
            for t in st.targets:
                if isinstance(t, ast.Name):
                    last[t.id] = f"{prefix}:L{st.lineno}:ass"
            for nm in _names_in(st.value):
                if nm in last or nm in {"input", "open"}:
                    pass
        if isinstance(st, ast.If):
            _build_last_def(st.body, dict(last), f"{prefix}:iT")
            _build_last_def(st.orelse, dict(last), f"{prefix}:iF")
        if isinstance(st, (ast.For, ast.While)):
            _build_last_def(st.body, last, f"{prefix}:lp")


def _emit_dfg(
    body: list[ast.stmt],
    graph: nx.DiGraph,
    scope: str,
    last: dict[str, str],
    prefix: str,
) -> None:
    for st in body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(st, ast.Assign):
            for t in st.targets:
                if isinstance(t, ast.Name):
                    last[t.id] = f"{prefix}:L{st.lineno}:ass"
        elif isinstance(st, (ast.AnnAssign, ast.AugAssign)) and st.target and isinstance(
            st.target, ast.Name
        ):
            last[st.target.id] = f"{prefix}:L{st.lineno}:ass"
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
            for nm in _names_in(st.value):
                if nm not in last:
                    continue
                d_node = f"dfgdef:{scope}:{last[nm]}"
                u_node = f"dfguse:{scope}:L{st.lineno}:{nm}"
                graph.add_edge(
                    d_node, u_node, type="dfg", var=nm, source_file=scope, line=st.lineno
                )
        if isinstance(st, ast.If):
            emit = dict(last)
            _emit_dfg(st.body, graph, scope, emit, f"{prefix}:iT")
            emit2 = dict(last)
            _emit_dfg(st.orelse, graph, scope, emit2, f"{prefix}:iF")
        if isinstance(st, (ast.For, ast.While)):
            emit = dict(last)
            _emit_dfg(st.body, graph, scope, emit, f"{prefix}:lp")


def build_python_dfg(
    graph: nx.DiGraph,
    scope_id: str,
    attrs: dict,
    *,
    repo_root: Optional[Path] = None,
) -> DfgResult:
    rel = str(attrs.get("source_file") or "")
    start_line = int(
        (attrs.get("span") or {}).get("start", {}).get("line")
        or attrs.get("start_line")
        or attrs.get("lineno")
        or 0
    )
    end_line = int(
        (attrs.get("span") or {}).get("end", {}).get("line")
        or attrs.get("end_line")
        or start_line
        or 0
    )
    if not rel or not start_line:
        return DfgResult(error="missing source span")
    qname = str(attrs.get("qualname") or attrs.get("qualified_name") or attrs.get("name") or "")

    src = _cfg._read_source(repo_root, rel)  # noqa: SLF001
    if not src:
        return DfgResult(error="unreadable source")
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError as e:
        return DfgResult(error=f"syntax: {e}")
    if not isinstance(tree, ast.Module):
        return DfgResult(error="not a module")
    fn = _cfg._find_function(  # noqa: SLF001
        tree, qualname=qname, start_line=start_line, end_line=end_line or start_line
    )
    if fn is None:
        fn = _cfg._fallback_by_line(  # noqa: SLF001
            tree, start_line, end_line or start_line + 200
        )
    if fn is None or not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return DfgResult(error="function not found")

    last: dict[str, str] = {a.arg: f"param:{a.arg}" for a in fn.args.args}
    for arg in last:
        graph.add_node(
            f"dfgdef:{scope_id}:{last[arg]}", type="dfg_node", var=arg, role="param", scope=scope_id
        )
    _emit_dfg(list(fn.body), graph, scope_id, last, f"py:{scope_id}")
    edges: list[tuple[str, str, str]] = []
    for u, v, d in graph.edges(data=True):
        if d.get("type") == "dfg" and d.get("source_file") == scope_id:
            edges.append((u, v, str(d.get("var", ""))))
    return DfgResult(dfg_edges=edges)
