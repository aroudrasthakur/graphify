"""JS/TS CFG/DFG/taint: await edges, flags, and DFG reachability (Phase 1b)."""
from __future__ import annotations

import networkx as nx
import pytest

from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import TaintEdge


def test_await_inserts_await_suspend_cfg_edge(tmp_path) -> None:
    (tmp_path / "api.mjs").write_text(
        "\n".join(
            [
                "async function handler() {",
                "  await Promise.resolve(1);",
                "  return 0;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    g = nx.DiGraph()
    g.add_node(
        "js_async_fn",
        language="javascript",
        source_file="api.mjs",
        span={"start": {"line": 1}, "end": {"line": 6}},
        entity_kind="function_declaration",
        name="handler()",
    )
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.cfg_available.get("js_async_fn") is True
    assert ctx.dfg_available.get("js_async_fn") is True
    await_edges = [
        (u, v, d)
        for u, v, d in g.edges(data=True)
        if d.get("type") == "cfg" and d.get("kind") == "await_suspend"
    ]
    assert await_edges, "expected at least one await_suspend CFG edge"


def test_closing_scope_dfg_emits_taint_for_eval_source(tmp_path) -> None:
    """Closure-like pattern: use req.query in eval → taint + DFG edges on scope."""
    (tmp_path / "r.js").write_text(
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
        "jsfn2",
        language="javascript",
        source_file="r.js",
        span={"start": {"line": 1}, "end": {"line": 6}},
        entity_kind="function_declaration",
    )
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.taint_edges_available.get("jsfn2") is True
    taint = g.graph.get("taint_edges", [])
    assert taint
    assert all(isinstance(x, TaintEdge) for x in taint)


@pytest.mark.parametrize(
    "source,rel",
    [
        ("function f(){ return 1; }", "plain.js"),
    ],
)
def test_jsts_flags_true_when_parseable(tmp_path, source, rel) -> None:
    (tmp_path / rel).write_text(source, encoding="utf-8")
    g = nx.DiGraph()
    g.add_node(
        "j1",
        language="javascript",
        source_file=rel,
        span={"start": {"line": 1}, "end": {"line": 3}},
        entity_kind="function_declaration",
    )
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.cfg_available.get("j1") is True
    assert ctx.dfg_available.get("j1") is True
