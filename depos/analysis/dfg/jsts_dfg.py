"""JS/TS def-use edges on tree-sitter (Phase 1b) — block-recursive for if/for/try.

Lexical ``let``/``const``/``var`` and branch-scoped env copies cover many cases; full
inter-procedural closure capture (values closed over from outer decls) is a later
improvement on top of this intra-procedural def-use.
"""
from __future__ import annotations

from copy import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import networkx as nx
from tree_sitter import Parser

from depos.analysis.cfg.jsts import _find_innermost_function, _get_function_body, _load_language_for_path


@dataclass
class DfgResult:
    dfg_edges: list[tuple[str, str, str]] = field(default_factory=list)
    error: Optional[str] = None


def _read_bytes(repo_root: Optional[Path], rel_path: str) -> Optional[bytes]:
    if not repo_root or not rel_path:
        return None
    path = (repo_root / rel_path).resolve()
    if not path.is_file():
        return None
    return path.read_bytes()


def _parse(rel_path: str, source: bytes) -> Any:
    lang = _load_language_for_path(rel_path)
    return Parser(lang).parse(source)


def _node_within(ancestor, n) -> bool:
    return int(ancestor.start_byte) <= int(n.start_byte) and int(n.end_byte) <= int(ancestor.end_byte)


def _identifier_in_type_position(n) -> bool:
    """Exclude identifiers in ``as T``, ``satisfies T``, and type annotations (TS)."""
    p = n.parent
    if p is not None and p.type == "satisfies_expression" and n.type == "type_identifier":
        return True
    while p is not None:
        pt = p.type
        if pt in (
            "type_annotation",
            "type_arguments",
            "type_parameters",
        ):
            return True
        if pt == "as_expression":
            t = p.child_by_field_name("type")
            if t is not None and _node_within(t, n):
                return True
            seen_as = False
            for ch in p.children:
                if ch.type == "as":
                    seen_as = True
                    continue
                if not ch.is_named:
                    continue
                if seen_as and _node_within(ch, n):
                    return True
        if pt == "satisfies_expression":
            t = p.child_by_field_name("type")
            if t is not None and _node_within(t, n):
                return True
        if pt in (
            "asserts",
            "assert_clause",
        ):
            return True
        p = p.parent
    return False


def _value_identifiers(node) -> set[str]:
    """Identifiers in value positions (not in type / assertion RHS)."""
    out: set[str] = set()
    stack: list = [node]
    while stack:
        n = stack.pop()
        for c in n.children:
            if c.is_named:
                stack.append(c)
        if n.type not in (
            "identifier",
            "property_identifier",
            "shorthand_property_identifier",
        ) or not n.text:
            continue
        if _identifier_in_type_position(n):
            continue
        out.add(n.text.decode("utf-8", errors="replace"))
    return out


def _record_lexical(
    st,
    last: dict[str, str],
    prefix: str,
) -> None:
    if st.type != "lexical_declaration":
        return
    for d in st.named_children:
        if d.type != "variable_declarator":
            continue
        name = d.child_by_field_name("name")
        if name and name.type == "identifier" and name.text:
            nm = name.text.decode("utf-8", errors="replace")
            line = int(name.start_point[0]) + 1
            last[nm] = f"{prefix}:L{line}:lex"
        if name and name.type == "destructuring_pattern":
            for ch in name.named_children:
                if ch.type in ("shorthand_property_identifier_pattern", "identifier") and ch.text:
                    nm = ch.text.decode("utf-8", errors="replace")
                    line = int(ch.start_point[0]) + 1
                    last[nm] = f"{prefix}:L{line}:destr"


def _emit_call_use(
    ex,
    graph: nx.DiGraph,
    scope_id: str,
    last: dict[str, str],
) -> DfgResult:
    r = DfgResult()
    if ex is None or ex.type != "call_expression":
        return r
    line = int(ex.start_point[0]) + 1
    for name in _value_identifiers(ex):
        if name not in last:
            continue
        d_node = f"dfgdef:{scope_id}:{last[name]}"
        u_node = f"dfguse:{scope_id}:L{line}:{name}"
        graph.add_edge(
            d_node, u_node, type="dfg", var=name, source_file=scope_id, line=line
        )
        r.dfg_edges.append((d_node, u_node, name))
    return r


def _for_header_defs(st, last: dict[str, str], prefix: str) -> None:
    if st.type not in ("for_statement", "for_in_statement", "for_of_statement"):
        return
    for ch in st.named_children:
        if ch.type not in (
            "variable_declaration",
            "lexical_declaration",
            "identifier",
        ):
            continue
        if ch.type == "lexical_declaration" or ch.type == "variable_declaration":
            for d in ch.named_children:
                if d.type == "variable_declarator":
                    nm = d.child_by_field_name("name")
                    if nm and nm.type == "identifier" and nm.text:
                        name = nm.text.decode("utf-8", "replace")
                        line = int(nm.start_point[0]) + 1
                        last[name] = f"{prefix}:L{line}:for"


def _walk(
    st,
    graph: nx.DiGraph,
    scope_id: str,
    last: dict[str, str],
    prefix: str,
) -> DfgResult:
    res = DfgResult()
    t = st.type
    if t in ("if_statement",):
        c = st.child_by_field_name("consequence")
        alt = st.child_by_field_name("alternative")
        l2 = copy(last)
        if c:
            if c.type == "statement_block":
                for sub in c.named_children:
                    res.dfg_edges.extend(
                        _walk(sub, graph, scope_id, l2, prefix + ":ifT").dfg_edges
                    )
            else:
                res.dfg_edges.extend(_walk(c, graph, scope_id, l2, prefix + ":ifT").dfg_edges)
        if alt:
            l3 = copy(last)
            if alt.type == "statement_block":
                for sub in alt.named_children:
                    res.dfg_edges.extend(
                        _walk(sub, graph, scope_id, l3, prefix + ":ifF").dfg_edges
                    )
            else:
                res.dfg_edges.extend(
                    _walk(alt, graph, scope_id, l3, prefix + ":ifF").dfg_edges
                )
        return res
    if t in ("for_statement", "for_in_statement", "for_of_statement"):
        _for_header_defs(st, last, prefix)
        body = st.child_by_field_name("body")
        if body and body.type == "statement_block":
            l2 = copy(last)
            for sub in body.named_children:
                res.dfg_edges.extend(_walk(sub, graph, scope_id, l2, prefix + ":lp").dfg_edges)
        return res
    if t in ("while_statement", "do_statement"):
        body = st.child_by_field_name("body")
        if body and body.type == "statement_block":
            l2 = copy(last)
            for sub in body.named_children:
                res.dfg_edges.extend(_walk(sub, graph, scope_id, l2, prefix + ":wh").dfg_edges)
        return res
    if t in ("with_statement",):
        body = st.child_by_field_name("body")
        if body and body.type == "statement_block":
            l2 = copy(last)
            for sub in body.named_children:
                res.dfg_edges.extend(
                    _walk(sub, graph, scope_id, l2, prefix + ":with").dfg_edges
                )
        return res
    if t == "try_statement":
        b = st.child_by_field_name("body")
        if b and b.type == "statement_block":
            l2 = copy(last)
            for sub in b.named_children:
                res.dfg_edges.extend(_walk(sub, graph, scope_id, l2, prefix + ":try").dfg_edges)
        h = st.child_by_field_name("handler")
        if h and h.type == "catch_clause":
            cb = h.child_by_field_name("body")
            if cb and cb.type == "statement_block":
                l3 = copy(last)
                for sub in cb.named_children:
                    res.dfg_edges.extend(_walk(sub, graph, scope_id, l3, prefix + ":ct").dfg_edges)
        return res
    if t == "switch_statement":
        b = st.child_by_field_name("body")
        if b is not None:
            for case in b.named_children:
                if case.type in ("switch_case", "switch_default") and case.named_children:
                    for ch in case.named_children:
                        if ch.type == "statement_block":
                            l2 = copy(last)
                            for sub in ch.named_children:
                                res.dfg_edges.extend(
                                    _walk(sub, graph, scope_id, l2, prefix + ":sw").dfg_edges
                                )
        return res
    if t == "statement_block":
        l2 = copy(last)
        for sub in st.named_children:
            res.dfg_edges.extend(_walk(sub, graph, scope_id, l2, prefix).dfg_edges)
        return res
    if t == "lexical_declaration":
        _record_lexical(st, last, prefix)
        return res
    if t == "expression_statement":
        ex = st.named_children[0] if st.named_children else None
        r2 = _emit_call_use(ex, graph, scope_id, last) if ex else DfgResult()
        res.dfg_edges.extend(r2.dfg_edges)
        return res
    return res


def build_jsts_dfg(
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
    if not rel or not start_line:
        return DfgResult(error="missing source span")
    if not str(rel).lower().endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")):
        return DfgResult(error="not a JS/TS file")

    raw = _read_bytes(repo_root, rel)
    if not raw:
        return DfgResult(error="unreadable source")
    try:
        tree = _parse(rel, raw)
    except Exception as e:  # noqa: BLE001
        return DfgResult(error=f"parse: {e}")

    fn = _find_innermost_function(tree.root_node, start_line)
    if fn is None:
        return DfgResult(error="function not found")

    body = _get_function_body(fn)
    if body is None:
        return DfgResult(error="no body")

    res = DfgResult()
    last: dict[str, str] = {}
    if body.type == "statement_block":
        for st in body.named_children:
            res.dfg_edges.extend(
                _walk(st, graph, scope_id, last, f"{scope_id}").dfg_edges
            )
    else:
        # expression-bodied arrow: single use site
        line = int(body.start_point[0]) + 1
        for name in _value_identifiers(body):
            if name in last:
                d_node = f"dfgdef:{scope_id}:{last[name]}"
                u_node = f"dfguse:{scope_id}:L{line}:{name}"
                graph.add_edge(
                    d_node, u_node, type="dfg", var=name, source_file=scope_id, line=line
                )
                res.dfg_edges.append((d_node, u_node, name))

    return res


__all__ = ["DfgResult", "build_jsts_dfg"]
