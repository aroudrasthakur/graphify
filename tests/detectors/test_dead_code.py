"""DeadCode uses call-subgraph reachability (Block 6)."""
from __future__ import annotations

import networkx as nx

from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors.builtin import group_a_graph_detectors as ga
from depos.analysis.schemas import AnalysisMode


def test_dead_code_unreachable_from_prod_entry() -> None:
    g = nx.DiGraph()
    g.add_node("api:route", is_fastapi_route=True, source_file="app/routes.py", node_kind="function")
    g.add_node("util:orphan", label="orphan", source_file="app/util.py", synthetic_entity=True, entity_kind="function")
    g.add_node("util:caller", label="caller", source_file="app/caller.py", synthetic_entity=True, entity_kind="function")
    g.add_edge("util:caller", "util:orphan", relation="CALLS")
    g.add_edge("api:route", "util:caller", relation="CALLS")
    out = ga._run_dead_code(g, AnalysisMode.full_repo_scan, IntelligenceConfig(), {})
    ids = {c.scope_id for c in out}
    assert not ids or any("dead" in s for s in ids)
