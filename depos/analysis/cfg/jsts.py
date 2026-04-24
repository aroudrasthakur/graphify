"""JavaScript/TypeScript CFG — hand-rolled on tree-sitter (Phase 1b, plan D4).

Builds ``type=\"cfg\"`` edges between basic-block style nodes for function bodies.
No Babel/Acorn/tsc.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import networkx as nx
from tree_sitter import Language, Parser

_FUNC_TYPES = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "arrow_function",
    }
)


@dataclass
class CfgResult:
    block_ids: list[str] = field(default_factory=list)
    error: Optional[str] = None


def _load_language_for_path(rel_path: str) -> Language:
    ext = Path(rel_path).suffix.lower()
    if ext in (".ts", ".tsx", ".mts", ".cts"):
        mod = importlib.import_module("tree_sitter_typescript")
        fn = getattr(mod, "language_typescript", None) or getattr(mod, "language", None)
    else:
        mod = importlib.import_module("tree_sitter_javascript")
        fn = getattr(mod, "language", None)
    if fn is None:
        raise RuntimeError("tree-sitter language constructor not found")
    return Language(fn())


def read_source_bytes(repo_root: Optional[Path], rel_path: str) -> Optional[bytes]:
    """Read file bytes from ``repo_root / rel_path`` if the file exists."""
    return _read_bytes_impl(repo_root, rel_path)


def _read_bytes_impl(repo_root: Optional[Path], rel_path: str) -> Optional[bytes]:
    if not repo_root or not rel_path:
        return None
    path = (repo_root / rel_path).resolve()
    if not path.is_file():
        return None
    return path.read_bytes()


def _parse_tree(rel_path: str, source: bytes) -> Any:
    lang = _load_language_for_path(rel_path)
    parser = Parser(lang)
    return parser.parse(source)


def _line1(node) -> int:
    return int(node.start_point[0]) + 1


def _find_innermost_function(root, line: int) -> Any | None:
    """Smallest function/method/arrow node whose source range contains ``line`` (1-based)."""
    best: Any | None = None
    best_size = 10**18

    def consider(n) -> None:
        nonlocal best, best_size
        if n.type in _FUNC_TYPES:
            sl = int(n.start_point[0]) + 1
            el = int(n.end_point[0]) + 1
            if sl <= line <= el:
                size = int(n.end_byte) - int(n.start_byte)
                if size < best_size:
                    best, best_size = n, size

    stack = [root]
    while stack:
        n = stack.pop()
        consider(n)
        for c in reversed(n.children):
            stack.append(c)
    return best


def _iter_statement_children(block) -> list:
    if block is None:
        return []
    return [c for c in block.children if c.is_named]


def _get_function_body(fn_node) -> Any | None:
    if fn_node.type == "arrow_function":
        body = fn_node.child_by_field_name("body")
        if body is None:
            return None
        if body.type == "statement_block":
            return body
        # Expression body: single virtual step
        return body
    body = fn_node.child_by_field_name("body")
    return body


def _linear_cfg(
    g: nx.DiGraph,
    base: str,
    parent_scope: str,
    body_node,
) -> CfgResult:
    r = CfgResult()
    if body_node is None:
        r.error = "no body"
        return r
    if body_node.type != "statement_block":
        # Single expression (arrow) — one synthetic block
        entry = f"{base}:entry"
        g.add_node(
            entry,
            type="cfg_block",
            parent_scope=parent_scope,
            label="entry",
        )
        nid = f"{base}:arrow_expr:{_line1(body_node)}"
        g.add_node(
            nid,
            type="cfg_block",
            parent_scope=parent_scope,
            stmt=body_node.type,
            line=_line1(body_node),
        )
        g.add_edge(entry, nid, type="cfg", kind="sequential")
        g.add_node(f"{base}:exit", type="cfg_block", parent_scope=parent_scope, label="exit")
        g.add_edge(nid, f"{base}:exit", type="cfg", kind="fallthrough")
        r.block_ids = [entry, nid, f"{base}:exit"]
        return r

    statements = _iter_statement_children(body_node)
    if not statements:
        entry = f"{base}:entry"
        ex = f"{base}:exit"
        g.add_node(entry, type="cfg_block", parent_scope=parent_scope, label="entry")
        g.add_node(ex, type="cfg_block", parent_scope=parent_scope, label="exit")
        g.add_edge(entry, ex, type="cfg", kind="empty")
        r.block_ids = [entry, ex]
        return r

    prev = f"{base}:entry"
    g.add_node(prev, type="cfg_block", parent_scope=parent_scope, label="entry")
    r.block_ids.append(prev)

    for st in statements:
        edge_kind = "sequential"
        if st.type == "expression_statement" and st.named_children:
            _inner = st.named_children[0]
            if _inner.type == "await_expression":
                edge_kind = "await_suspend"
        nid = f"{base}:stmt:{_line1(st)}:{st.type}"
        node_attr: dict = {
            "type": "cfg_block",
            "parent_scope": parent_scope,
            "stmt": st.type,
            "line": _line1(st),
        }
        if edge_kind == "await_suspend":
            node_attr["await_suspension"] = True
        g.add_node(nid, **node_attr)
        g.add_edge(prev, nid, type="cfg", kind=edge_kind)
        r.block_ids.append(nid)
        if st.type in (
            "for_statement",
            "for_in_statement",
            "for_of_statement",
            "while_statement",
            "do_statement",
            "with_statement",
            "using_declaration",
        ):
            g.add_edge(nid, nid, type="cfg", kind="back_edge")
        elif st.type == "if_statement":
            alt = st.child_by_field_name("alternative")
            if alt is not None:
                a_start = f"{base}:else:{_line1(alt)}"
                g.add_node(
                    a_start,
                    type="cfg_block",
                    parent_scope=parent_scope,
                    label="else",
                )
                g.add_edge(nid, a_start, type="cfg", kind="if_false")
                r.block_ids.append(a_start)
        elif st.type == "switch_statement":
            sw_body = st.child_by_field_name("body")
            if sw_body is not None:
                for case in sw_body.named_children:
                    if case.type in ("switch_case", "switch_default"):
                        cid = f"{base}:case:{_line1(case)}"
                        g.add_node(
                            cid,
                            type="cfg_block",
                            parent_scope=parent_scope,
                            stmt=case.type,
                            line=_line1(case),
                        )
                        g.add_edge(nid, cid, type="cfg", kind="switch_case")
                        r.block_ids.append(cid)
        elif st.type == "try_statement":
            fin = st.child_by_field_name("finalizer")
            if fin is not None and fin.type == "finally_clause":
                fnid = f"{base}:finally:{_line1(fin)}"
                g.add_node(fnid, type="cfg_block", parent_scope=parent_scope, label="finally")
                g.add_edge(nid, fnid, type="cfg", kind="try_finally")
                r.block_ids.append(fnid)
            hand = st.child_by_field_name("handler")
            if hand is not None and hand.type == "catch_clause":
                hn = f"{base}:catch:{_line1(hand)}"
                g.add_node(hn, type="cfg_block", parent_scope=parent_scope, label="catch")
                g.add_edge(nid, hn, type="cfg", kind="try_catch")
                r.block_ids.append(hn)
        elif st.type == "labeled_statement":
            lid = f"{base}:labeled:{_line1(st)}"
            g.add_node(
                lid,
                type="cfg_block",
                parent_scope=parent_scope,
                stmt="labeled",
                line=_line1(st),
            )
            g.add_edge(nid, lid, type="cfg", kind="label")
            r.block_ids.append(lid)
        prev = nid

    g.add_node(f"{base}:exit", type="cfg_block", parent_scope=parent_scope, label="exit")
    g.add_edge(prev, f"{base}:exit", type="cfg", kind="fallthrough")
    r.block_ids.append(f"{base}:exit")
    return r


def build_jsts_function_cfg(
    graph: nx.DiGraph,
    scope_id: str,
    attrs: dict,
    *,
    repo_root: Optional[Path] = None,
) -> CfgResult:
    rel = str(attrs.get("source_file") or "")
    start_line = int(
        (attrs.get("span") or {}).get("start", {}).get("line")
        or attrs.get("start_line")
        or attrs.get("lineno")
        or 0
    )
    if not rel or not start_line:
        return CfgResult(error="missing source span")
    if not str(rel).lower().endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")):
        return CfgResult(error="not a JS/TS file")

    raw = _read_bytes_impl(repo_root, rel)
    if not raw:
        return CfgResult(error="unreadable source")
    try:
        tree = _parse_tree(rel, raw)
    except Exception as e:  # noqa: BLE001
        return CfgResult(error=f"parse: {e}")

    fn = _find_innermost_function(tree.root_node, start_line)
    if fn is None:
        return CfgResult(error="function not found in tree-sitter tree")

    body = _get_function_body(fn)
    base = f"js_cfg:{scope_id}"
    return _linear_cfg(graph, base, parent_scope=scope_id, body_node=body)


__all__ = ["CfgResult", "build_jsts_function_cfg", "read_source_bytes"]
