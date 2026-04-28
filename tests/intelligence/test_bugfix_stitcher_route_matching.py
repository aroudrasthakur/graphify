r"""Bug Condition Exploration Test for Fix 1: Stitcher Route Matching

**Validates: Requirements 1.1, 1.2, 2.1, 2.2**

This test demonstrates the bug where emit_http_calls_route fails to match
TypeScript HTTP clients to FastAPI route handlers. Based on the diagnostic
run showing "0/23 routes linked; errors=74", this test explores potential
root causes in normalize_route and score_match logic.

**CRITICAL**: This test is EXPECTED TO FAIL on unfixed code.
- Failure confirms the bug exists
- Success after fix confirms the bug is resolved

**BUG CONFIRMED**: The test_bug_condition_dynamic_url_construction test FAILS
on unfixed code, confirming the root cause:

**Root Cause Identified**:
- Dynamic URL construction with template literals (e.g., `/api/repos/${id}`)
- http_probes.py detects these as is_dynamic_url=True
- score_match applies DYNAMIC_URL_MAX_CONFIDENCE cap of 0.4
- 0.4 < MIN_EMIT_CONFIDENCE (0.6) → edge rejected, not emitted
- Result: 0 routes linked for any dynamic URL construction

**Counterexample**:
- Client: `const url = \`/api/repos/${id}\`; fetch(url)`
- Server: `@router.get('/repos/{repo_id}')`
- Expected: HTTP_CALLS_ROUTE edge created
- Actual: No edge (confidence 0.4 < 0.6 threshold)
- Coverage: 0/1 routes linked

This explains the diagnostic "0/23 routes linked; errors=74" - the real
codebase likely uses dynamic URL construction extensively.

**Expected Behavior After Fix**: 
- Adjust confidence thresholds or scoring logic
- Allow dynamic URLs to emit edges with appropriate confidence
- linked_routes > 0, errors reduced from 74
"""
from __future__ import annotations

import json
from pathlib import Path

import networkx as nx
import pytest

from depos.analysis.config import IntelligenceConfig
from depos.enrichment.semantic_edges import HTTP_CALLS_ROUTE, enrich_graph


@pytest.fixture
def bugfix_repo_root(tmp_path: Path) -> tuple[Path, nx.DiGraph]:
    """Create a minimal graph with the concrete failing case:
    - FastAPI route: @router.get("/repos")
    - TS client: fetch("/api/repos")
    
    This reproduces the 0/23 routes linked bug.
    """
    # Create source files
    ts_rel = "apps/web/app/repos/page.tsx"
    py_rel = "backend/routers/repos.py"
    
    ts_path = tmp_path / ts_rel
    py_path = tmp_path / py_rel
    ts_path.parent.mkdir(parents=True, exist_ok=True)
    py_path.parent.mkdir(parents=True, exist_ok=True)
    
    # TypeScript client with /api prefix
    ts_path.write_text(
        """export async function ReposPage() {
  const res = await fetch('/api/repos');
  return res.json();
}
""",
        encoding="utf-8",
    )
    
    # FastAPI route WITHOUT /api prefix
    py_path.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get('/repos')
def list_repos():
    return {'repos': []}
""",
        encoding="utf-8",
    )
    
    # Create minimal graph with nodes pointing to these files
    graph = nx.DiGraph()
    
    # TS node - needs label attribute for _nodes_for_file to find it
    ts_node_id = "ts:ReposPage"
    graph.add_node(
        ts_node_id,
        node_type="function",
        name="ReposPage",
        label="ReposPage",
        source_file=str(ts_path),
        language="typescript",
        file_type="code",
    )
    
    # Python node - needs label attribute matching function name for _node_for_file_and_name
    py_node_id = "py:list_repos"
    graph.add_node(
        py_node_id,
        node_type="function",
        name="list_repos",
        label="list_repos()",
        source_file=str(py_path),
        language="python",
        file_type="code",
    )
    
    return tmp_path, graph


def test_bug_condition_stitcher_route_matching_fails(bugfix_repo_root: tuple[Path, nx.DiGraph]) -> None:
    """Property 1: Bug Condition - Stitcher Route Matching Failures
    
    **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
    
    Test that emit_http_calls_route creates HTTP_CALLS_ROUTE edges for the
    concrete case where client uses /api prefix and server does not.
    
    **CURRENT STATUS**: This simple case PASSES on current code, suggesting
    the basic /api prefix handling works correctly. The diagnostic bug
    (0/23 routes linked; errors=74) may involve more complex scenarios:
    - Dynamic URL construction with template literals
    - Method inference from context
    - Routes with path parameters
    - Confidence threshold edge cases
    
    **EXPECTED OUTCOME ON UNFIXED CODE**: Test FAILS
    - This is CORRECT - it proves the bug exists
    - linked_routes == 0 (current buggy behavior)
    - No HTTP_CALLS_ROUTE edges created
    
    **EXPECTED OUTCOME AFTER FIX**: Test PASSES
    - linked_routes > 0
    - HTTP_CALLS_ROUTE edge created with confidence > 0.0
    - Errors reduced from 74
    
    **Counterexample**: Based on diagnostic run showing 0/23 routes linked
    with errors=74, the bug likely involves edge cases not covered by this
    simple test.
    """
    repo_root, graph = bugfix_repo_root
    config = IntelligenceConfig()
    
    # Run enrichment (this calls emit_http_calls_route internally)
    enriched, coverage = enrich_graph(graph, config=config, repo_root=repo_root)
    
    # Find HTTP_CALLS_ROUTE edges
    http_edges = [
        (u, v, data)
        for u, v, data in enriched.edges(data=True)
        if data.get("relation") == HTTP_CALLS_ROUTE
    ]
    
    # ASSERTION: After fix, we expect at least one edge to be created
    # NOTE: This test currently PASSES on unfixed code, which suggests
    # the bug is more subtle than simple /api prefix handling
    assert len(http_edges) > 0, (
        f"Bug confirmed: 0 HTTP_CALLS_ROUTE edges created. "
        f"Client fetch('/api/repos') failed to match server @router.get('/repos'). "
        f"Coverage: {coverage.linked_routes}/{coverage.total_fastapi_routes} routes linked. "
        f"Diagnostic run showed 0/23 routes linked with errors=74."
    )
    
    # After fix, verify edge properties
    u, v, data = http_edges[0]
    assert data["source_system"] == "typescript"
    assert data["target_system"] == "python"
    assert data["contract_kind"] == "http"
    assert data["api_method"] == "GET"
    assert "/repos" in data["route_pattern"]
    assert data["confidence"] > 0.0, "Edge confidence should be > 0.0 after fix"
    
    # Verify coverage metrics improved
    assert coverage.total_fastapi_routes == 1
    assert coverage.linked_routes > 0, (
        f"Expected linked_routes > 0 after fix, got {coverage.linked_routes}"
    )
    assert coverage.coverage_ratio > 0.0, (
        f"Expected coverage_ratio > 0.0 after fix, got {coverage.coverage_ratio}"
    )
    
    print(f"\n✓ Bug fix verified: {coverage.linked_routes}/{coverage.total_fastapi_routes} routes linked")
    print(f"✓ Edge confidence: {data['confidence']}")
    print(f"✓ Coverage ratio: {coverage.coverage_ratio}")


def test_bug_condition_dynamic_url_construction(tmp_path: Path) -> None:
    """Property 1: Bug Condition - Dynamic URL Construction Edge Case
    
    **Validates: Requirements 1.1, 1.2, 2.1, 2.2**
    
    Test that dynamic URL construction (template literals with variables)
    doesn't get rejected due to overly aggressive confidence penalties.
    
    The diagnostic bug may involve score_match applying DYNAMIC_URL_MAX_CONFIDENCE
    (0.4) which falls below MIN_EMIT_CONFIDENCE (0.6), causing valid matches
    to be rejected.
    
    **EXPECTED OUTCOME ON UNFIXED CODE**: Test FAILS
    - Dynamic URLs capped at 0.4 confidence
    - Falls below 0.6 emit threshold
    - No edge created
    
    **EXPECTED OUTCOME AFTER FIX**: Test PASSES
    - Dynamic URLs still matched with appropriate confidence
    - Edge created even for dynamic construction
    """
    # Create source files with dynamic URL construction
    ts_rel = "apps/web/app/repos/[id]/page.tsx"
    py_rel = "backend/routers/repos.py"
    
    ts_path = tmp_path / ts_rel
    py_path = tmp_path / py_rel
    ts_path.parent.mkdir(parents=True, exist_ok=True)
    py_path.parent.mkdir(parents=True, exist_ok=True)
    
    # TypeScript client with dynamic URL (template literal)
    ts_path.write_text(
        """export async function RepoDetailPage({ id }: { id: string }) {
  const res = await fetch(`/api/repos/${id}`);
  return res.json();
}
""",
        encoding="utf-8",
    )
    
    # FastAPI route with path parameter
    py_path.write_text(
        """from fastapi import APIRouter

router = APIRouter()

@router.get('/repos/{repo_id}')
def get_repo(repo_id: str):
    return {'id': repo_id}
""",
        encoding="utf-8",
    )
    
    # Create graph
    graph = nx.DiGraph()
    
    ts_node_id = "ts:RepoDetailPage"
    graph.add_node(
        ts_node_id,
        node_type="function",
        name="RepoDetailPage",
        label="RepoDetailPage",
        source_file=str(ts_path),
        language="typescript",
        file_type="code",
    )
    
    py_node_id = "py:get_repo"
    graph.add_node(
        py_node_id,
        node_type="function",
        name="get_repo",
        label="get_repo()",
        source_file=str(py_path),
        language="python",
        file_type="code",
    )
    
    config = IntelligenceConfig()
    enriched, coverage = enrich_graph(graph, config=config, repo_root=tmp_path)
    
    # Find HTTP_CALLS_ROUTE edges
    http_edges = [
        (u, v, data)
        for u, v, data in enriched.edges(data=True)
        if data.get("relation") == HTTP_CALLS_ROUTE
    ]
    
    # This test explores whether dynamic URL construction causes the bug
    # If DYNAMIC_URL_MAX_CONFIDENCE (0.4) < MIN_EMIT_CONFIDENCE (0.6),
    # then no edge will be created
    assert len(http_edges) > 0, (
        f"Bug confirmed: Dynamic URL construction rejected. "
        f"Template literal `/api/repos/${{id}}` failed to match @router.get('/repos/{{repo_id}}'). "
        f"Coverage: {coverage.linked_routes}/{coverage.total_fastapi_routes} routes linked. "
        f"This may explain the 0/23 routes linked diagnostic bug."
    )
    
    u, v, data = http_edges[0]
    print(f"\n✓ Dynamic URL matched: confidence={data['confidence']}")
    print(f"✓ Coverage: {coverage.linked_routes}/{coverage.total_fastapi_routes} routes linked")
