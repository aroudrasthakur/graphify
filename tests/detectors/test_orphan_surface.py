"""OrphanSurface uses reachability from production entries (Block 6)."""
from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors.builtin import group_a_graph_detectors as ga
from depos.analysis.schemas import AnalysisMode


def test_orphan_route_not_reachable_from_prod_entry() -> None:
    g = nx.DiGraph()
    g.add_node("prod:page", node_kind="next_route", source_file="app/p.tsx")
    g.add_node("orph:page", node_kind="next_route", source_file="app/orphan/page.tsx")
    g.add_node("test:file", node_kind="next_route", source_file="__tests__/t.test.ts")
    g.add_edge("test:file", "orph:page", relation="CALLS")
    out = ga._run_orphan_surface(g, AnalysisMode.full_repo_scan, IntelligenceConfig(), {})
    anchors = {a for c in out for a in c.diff_anchors}
    assert "orph:page" in anchors
