"""JS/TS scope with full semantic flags: policy allows Group B/C (Phase 1b + registry)."""
from __future__ import annotations

import networkx as nx

from depos.analysis.detectors import get_detector
from depos.analysis.detectors.policy import DetectorPolicy
from depos.analysis.run_context import build_run_context


def test_jsts_scope_with_layers_allows_cfg_dfg_taint_detectors(tmp_path) -> None:
    (tmp_path / "api.ts").write_text(
        "function handler() {\n  while (true) {}\n  const x = 1 as number;\n  const y: any = 1;\n  y satisfies z;\n}\n",
        encoding="utf-8",
    )
    g = nx.DiGraph()
    g.add_node(
        "js_scope",
        language="typescript",
        source_file="api.ts",
        span={"start": {"line": 1}, "end": {"line": 20}},
        entity_kind="function_declaration",
    )
    ctx = build_run_context(g, manifest=None, repo_root=tmp_path)
    assert ctx.cfg_available.get("js_scope") is True
    assert ctx.dfg_available.get("js_scope") is True
    assert ctx.taint_edges_available.get("js_scope") is True

    pol = DetectorPolicy()
    assert pol.semantic_layer_satisfied(get_detector("infinite-loop"), ctx, "js_scope")
    assert pol.semantic_layer_satisfied(get_detector("sql-injection-approx"), ctx, "js_scope")
    assert pol.semantic_layer_satisfied(get_detector("uninit-variable-approx"), ctx, "js_scope")
