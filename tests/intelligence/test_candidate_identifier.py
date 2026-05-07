from __future__ import annotations

import networkx as nx

from depos.analysis.candidate_identifier import identify_candidates, resolve_change_manifest
from depos.analysis.config import IntelligenceConfig
from depos.analysis.run_context import build_run_context
from depos.analysis.schemas import AnalysisMode, SeedType


def test_candidate_identifier_seeds_public_surfaces_and_anomalies() -> None:
    graph = nx.DiGraph()
    graph.add_node(
        "py:route:list_repos",
        label="list_repos()",
        source_file="backend/routers/repos.py",
        is_fastapi_route=True,
        http_method="GET",
        route_pattern="/repos/{repo_id}",
    )
    graph.add_node(
        "ts:file:repos",
        label="ReposPage",
        source_file="apps/web/app/repos/page.tsx",
        http_call_sites=[{"url_literal": "/api/missing", "http_method": "GET"}],
    )
    graph.add_node(
        "py:auth:verify",
        label="verify_token()",
        source_file="depos/auth.py",
    )

    config = IntelligenceConfig(enable_lexical_seeds=True)
    m = resolve_change_manifest(graph, diff_path=None, manual_manifest=None, repo_root=None)
    rc = build_run_context(graph, m, repo_root=None, config=config)
    candidates, manifest, _ = identify_candidates(
        graph,
        run_context=rc,
        config=config,
        mode=AnalysisMode.full_repo_scan,
    )

    assert manifest.entries == []
    assert manifest.resolved_via == "empty"

    seed_types = {candidate.seed_type for candidate in candidates}
    assert SeedType.interface_surface in seed_types
    assert SeedType.graph_anomaly in seed_types
    assert SeedType.lexical_keyword in seed_types

    route_surface = [c for c in candidates if c.detector_payload.raw.get("surface_type") == "public_route"]
    assert route_surface

    unmatched_http = [c for c in candidates if c.detector_payload.raw.get("anomaly") == "unmatched_http_client_call"]
    assert unmatched_http
    assert unmatched_http[0].detector_payload.raw["urls"] == ["/api/missing"]

    auth_surface = [c for c in candidates if c.detector_payload.raw.get("surface_type") == "auth_boundary"]
    assert auth_surface


def test_enable_ai_driven_seeds_still_enables_lexical_keyword_seeds() -> None:
    graph = nx.DiGraph()
    graph.add_node(
        "n:auth",
        label="verify_token()",
        source_file="pkg/auth.py",
    )
    cfg = IntelligenceConfig(enable_ai_driven_seeds=True, enable_lexical_seeds=False)
    m = resolve_change_manifest(graph, diff_path=None, manual_manifest=None, repo_root=None)
    rc = build_run_context(graph, m, repo_root=None, config=cfg)
    candidates, _, _ = identify_candidates(
        graph,
        run_context=rc,
        config=cfg,
        mode=AnalysisMode.full_repo_scan,
    )
    assert any(c.seed_type == SeedType.lexical_keyword for c in candidates)
def test_candidate_identifier_keeps_file_only_diff_entries() -> None:
    graph = nx.DiGraph()
    config = IntelligenceConfig()
    manual_manifest = {
        "entries": [
            {
                "path": "supabase/migrations/20260418000000_drop_old_table.sql",
                "node_ids": [],
                "migration_change": True,
                "file_change": True,
            }
        ]
    }

    m = resolve_change_manifest(
        graph, diff_path=None, manual_manifest=manual_manifest, repo_root=None
    )
    rc = build_run_context(graph, m, repo_root=None, config=config)
    candidates, manifest, _ = identify_candidates(
        graph,
        run_context=rc,
        config=config,
        mode=AnalysisMode.diff_aware,
        manual_manifest=manual_manifest,
    )

    assert len(manifest.entries) == 1
    diff_candidates = [c for c in candidates if c.seed_type == SeedType.diff_anchor]
    assert diff_candidates
    assert diff_candidates[0].detector_payload.raw["file_only"] is True
    assert diff_candidates[0].detector_payload.raw["removed_entity_references"] == 1


def test_candidate_identifier_prefers_synthetic_entities_over_leaf_nodes() -> None:
    graph = nx.DiGraph()
    graph.add_node(
        "leaf:identifier",
        label="auth",
        source_file="frontend/src/auth.ts",
        kind="identifier",
    )
    graph.add_node(
        "entity:function:verify",
        label="verify_token()",
        source_file="backend/app/auth.py",
        synthetic_entity=True,
        entity_kind="function",
        embedded_text="def verify_token():\n    return True",
    )

    cfg = IntelligenceConfig(enable_lexical_seeds=True)
    m = resolve_change_manifest(graph, diff_path=None, manual_manifest=None, repo_root=None)
    rc = build_run_context(graph, m, repo_root=None, config=cfg)
    candidates, _, _ = identify_candidates(
        graph,
        run_context=rc,
        config=cfg,
        mode=AnalysisMode.full_repo_scan,
    )

    anchor_ids = {anchor for candidate in candidates for anchor in candidate.diff_anchors}
    assert "entity:function:verify" in anchor_ids
    assert "leaf:identifier" not in anchor_ids


def test_interface_surface_candidates_materialize_seam_endpoints() -> None:
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
    assert seam_candidates
    for candidate in seam_candidates:
        assert candidate.language_path == ["javascript", "python"]
        assert candidate.score.seam_exposure == candidate.seam_edges[0].risk
        for seam in candidate.seam_edges:
            assert seam.source != ""
            assert seam.target != ""
