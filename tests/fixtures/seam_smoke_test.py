from __future__ import annotations

import networkx as nx

from depos.analysis.candidate_identifier import identify_candidates, resolve_change_manifest
from depos.analysis.config import IntelligenceConfig
from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import AnalysisMode


graph = nx.DiGraph()
graph.add_node(
    "ts:file:repos",
    label="loadRepos()",
    source_file="apps/web/app/repos/page.tsx",
    language="javascript",
    http_call_sites=[{"url_literal": "/api/repos", "http_method": "GET"}],
)
graph.add_node(
    "py:route:list_repos",
    label="list_repos()",
    source_file="backend/routers/repos.py",
    language="python",
    is_fastapi_route=True,
    http_method="GET",
    route_pattern="/api/repos",
)
graph.add_edge(
    "ts:file:repos",
    "py:route:list_repos",
    relation="HTTP_CALLS_ROUTE",
    source_system="javascript",
    target_system="python",
)

config = IntelligenceConfig()
manifest = resolve_change_manifest(graph, diff_path=None, manual_manifest=None, repo_root=None)
run_context = build_run_context(graph, manifest, repo_root=None, config=config)
candidates, _, _ = identify_candidates(
    graph,
    run_context=run_context,
    config=config,
    mode=AnalysisMode.full_repo_scan,
)

seam_candidates = [candidate for candidate in candidates if candidate.seam_edges]
assert seam_candidates, "Expected at least one seam-backed candidate"
for candidate in seam_candidates:
    for seam in candidate.seam_edges:
        assert seam.source != "" and seam.target != "", (
            f"Blank seam endpoints on candidate {candidate.candidate_id}: {seam}"
        )

print(f"PASS — {len(seam_candidates)} seam-backed candidates, all endpoints resolved")
