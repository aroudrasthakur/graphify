"""Phase 1a/1b semantic layer acceptance (depOS master plan)."""
from __future__ import annotations

import networkx as nx

from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import TaintEdge


def test_phase1a_python_scope_flags_and_taint(tmp_path) -> None:
    (tmp_path / "handler.py").write_text(
        "\n".join(
            [
                "def handler():",
                "    import sqlite3",
                '    conn = sqlite3.connect(":memory:")',
                "    cur = conn.cursor()",
                '    cur.execute("select 1")',
                "",
            ]
        ),
        encoding="utf-8",
    )
    g = nx.DiGraph()
    g.add_node(
        "pyfn",
        language="python",
        source_file="handler.py",
        span={"start": {"line": 1}, "end": {"line": 20}},
        qualname="handler",
        entity_kind="function_definition",
        name="handler()",
    )
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.graph_metrics is not None
    ctx.graph_metrics_or_raise()
    assert ctx.cfg_available["pyfn"] is True
    assert ctx.dfg_available["pyfn"] is True
    assert ctx.taint_edges_available["pyfn"] is True
    taint = g.graph.get("taint_edges", [])
    assert taint
    assert all(isinstance(x, TaintEdge) for x in taint)


def test_phase1a_non_python_flags_false(tmp_path) -> None:
    (tmp_path / "readme.go").write_text("package main\nfunc F() {}\n", encoding="utf-8")
    g = nx.DiGraph()
    g.add_node(
        "go1",
        language="go",
        source_file="readme.go",
        span={"start": {"line": 2}, "end": {"line": 3}},
        qualname="F",
        entity_kind="function_declaration",
    )
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.cfg_available.get("go1") is None or ctx.cfg_available.get("go1") is False


def test_phase1b_javascript_function_flags(tmp_path) -> None:
    (tmp_path / "api.js").write_text(
        "\n".join(
            [
                "function handler(req) {",
                "  const q = req.query.x;",
                "  eval(q);",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    g = nx.DiGraph()
    g.add_node(
        "jsfn",
        language="javascript",
        source_file="api.js",
        span={"start": {"line": 1}, "end": {"line": 10}},
        entity_kind="function_declaration",
        name="handler()",
    )
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.cfg_available.get("jsfn") is True
    assert ctx.dfg_available.get("jsfn") is True
    assert ctx.taint_edges_available.get("jsfn") is True
    assert any(e[2].get("type") == "TAINT" for e in g.edges(data=True))
