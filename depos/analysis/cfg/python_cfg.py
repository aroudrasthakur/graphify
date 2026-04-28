"""Build CFG for Python function bodies (stdlib ``ast``)."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import networkx as nx

_PY_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
_STMT = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Return,
    ast.Delete,
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.For,
    ast.While,
    ast.If,
    ast.With,
    ast.AsyncWith,
    ast.Raise,
    ast.Try,
    ast.Assert,
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.Expr,
    ast.Pass,
    ast.Break,
    ast.Continue,
    ast.Match,
)


@dataclass
class CfgResult:
    block_ids: list[str] = field(default_factory=list)
    error: Optional[str] = None


def _read_source(repo_root: Optional[Path], rel_path: str) -> Optional[str]:
    if not repo_root or not rel_path:
        return None
    path = (repo_root / rel_path).resolve()
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _find_function(
    module: ast.Module, *, qualname: str, start_line: int, end_line: int
) -> Optional[ast.AST]:
    if not qualname or qualname == "<module>":
        for node in module.body:
            if isinstance(node, _PY_FUNCS) and start_line <= node.lineno and (
                getattr(node, "end_lineno", None) and getattr(node, "end_lineno", 0) >= start_line
            ):
                if abs(node.lineno - start_line) <= 2:
                    return node
    parts = qualname.split(".")
    current: list[ast.stmt] = list(module.body)
    target: ast.AST | None = None
    for i, part in enumerate(parts):
        found = None
        for stmt in current:
            if isinstance(stmt, _PY_FUNCS) and stmt.name == part:
                found = stmt
                break
        if found is None:
            return None
        target = found
        if i + 1 < len(parts) and isinstance(found, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current = list(found.body)
    if target and isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return target
    return None


def _fallback_by_line(
    module: ast.Module, start_line: int, end_line: int
) -> Optional[ast.AST]:
    best: Optional[ast.AST] = None
    for node in module.body:
        if isinstance(node, _PY_FUNCS) and start_line <= node.lineno and (
            not getattr(node, "end_lineno", None) or node.end_lineno <= (end_line or 10_000)  # type: ignore[union-attr]
        ):
            if best is None or node.lineno > best.lineno:  # type: ignore[union-attr]
                best = node
    return best


def _stmt_key(st: ast.stmt) -> str:
    return f"{st.lineno}:{type(st).__name__}"


def _linear_cfg_from_body(
    g: nx.DiGraph, base: str, body: list[ast.stmt], parent_scope: str
) -> CfgResult:
    """A linear sequence of basic blocks: entry -> s0 -> s1 -> ... -> exit."""
    r = CfgResult()
    if not body:
        return r
    prev = f"{base}:entry"
    g.add_node(prev, type="cfg_block", parent_scope=parent_scope, label="entry")
    r.block_ids.append(prev)
    for st in body:
        nid = f"{base}:stmt:{_stmt_key(st)}"
        g.add_node(
            nid,
            type="cfg_block",
            parent_scope=parent_scope,
            stmt=type(st).__name__,
            line=st.lineno,
        )
        g.add_edge(prev, nid, type="cfg", kind="sequential")
        r.block_ids.append(nid)
        if isinstance(st, (ast.For, ast.While)):
            _add_loop_back_edge(g, base, st, nid, parent_scope, r)
        if isinstance(st, ast.If):
            _add_if_edges(g, base, st, nid, parent_scope, r)
        prev = nid
    g.add_node(f"{base}:exit", type="cfg_block", parent_scope=parent_scope, label="exit")
    g.add_edge(prev, f"{base}:exit", type="cfg", kind="fallthrough")
    r.block_ids.append(f"{base}:exit")
    return r


def _add_if_edges(
    g: nx.DiGraph, base: str, node: ast.If, if_block: str, parent_scope: str, r: CfgResult
) -> None:
    t = f"{base}:if:{node.lineno}:then"
    g.add_node(t, type="cfg_block", parent_scope=parent_scope, label="if_then")
    g.add_edge(if_block, t, type="cfg", kind="if_true")
    r.block_ids.append(t)
    if node.orelse and isinstance(node.orelse[0], ast.If):
        _linear_cfg_from_body(g, f"{base}:elif{node.orelse[0].lineno}", node.orelse, parent_scope)
    elif node.orelse:
        fnode = f"{base}:if:{node.lineno}:else"
        g.add_node(fnode, type="cfg_block", parent_scope=parent_scope, label="if_else")
        g.add_edge(if_block, fnode, type="cfg", kind="if_false")
        r.block_ids.append(fnode)


def _add_loop_back_edge(
    g: nx.DiGraph, base: str, node: ast.AST, loop_head: str, parent_scope: str, r: CfgResult
) -> None:
    g.add_edge(loop_head, loop_head, type="cfg", kind="back_edge")


def build_python_function_cfg(
    graph: nx.DiGraph,
    scope_id: str,
    attrs: dict,
    *,
    repo_root: Optional[Path] = None,
) -> CfgResult:
    """Add CFG block nodes/edges to ``graph`` for a Python function scope node."""
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
        return CfgResult(error="missing source span")

    name = str(attrs.get("name") or attrs.get("label") or "").split("(")[0].strip() or "fn"
    qual = attrs.get("qualname") or attrs.get("qualified_name")
    if isinstance(qual, str):
        qname = qual
    else:
        qname = str(attrs.get("name") or "")

    src = _read_source(repo_root, rel)
    if not src:
        return CfgResult(error="unreadable source")
    try:
        tree = ast.parse(src, filename=rel)
    except SyntaxError as e:
        return CfgResult(error=f"syntax: {e}")

    assert isinstance(tree, ast.Module)
    fn = _find_function(tree, qualname=qname, start_line=start_line, end_line=end_line or start_line)
    if fn is None:
        fn = _fallback_by_line(tree, start_line, end_line or start_line + 200)
    if fn is None or not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return CfgResult(error="function not found in ast")

    base = f"py_cfg:{scope_id}"
    return _linear_cfg_from_body(graph, base, list(fn.body), parent_scope=scope_id)
