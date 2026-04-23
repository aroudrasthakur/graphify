"""Context bundle includes typed ``taint_edges`` when the neighborhood overlaps."""
from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.context_bundle import build_bundle
from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import AnalysisMode, Candidate, SeedType, TaintEdge


def test_build_bundle_includes_taint_edges_for_scope(tmp_path) -> None:
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
    assert g.graph.get("taint_edges")

    c = Candidate(
        candidate_id="c1",
        scope_id="pyfn",
        seed_type=SeedType.diff_anchor,
        diff_anchors=["pyfn"],
        analysis_mode=AnalysisMode.full_repo_scan,
    )
    config = IntelligenceConfig()
    bundle = build_bundle(g, c, config=config, source_roots=[tmp_path])
    assert len(bundle.taint_edges) >= 1
    assert all(isinstance(x, TaintEdge) for x in bundle.taint_edges)
    assert any(x.scope == "pyfn" for x in bundle.taint_edges)
