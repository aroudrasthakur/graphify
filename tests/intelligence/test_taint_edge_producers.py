"""Smoke: typed :class:`TaintEdge` emission from taint producers (Fix Block 2)."""
from __future__ import annotations

import networkx as nx

from depos.analysis.schemas import TaintEdge
from depos.analysis.run_context import build_run_context


def test_taint_edge_producer_emits_valid_model(tmp_path) -> None:
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
    build_run_context(g, manifest=None, repo_root=tmp_path)
    edges = g.graph.get("taint_edges", [])
    assert isinstance(edges, list)
    assert len(edges) >= 1
    te0 = edges[0]
    assert isinstance(te0, TaintEdge)
    TaintEdge.model_validate(te0.model_dump())
    assert te0.intermediate_path == [te0.source_node, te0.sink_node]
