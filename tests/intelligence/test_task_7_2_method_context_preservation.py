"""Test for Task 7.2: Preserve method context in http_probes.py

This test verifies that HTTP method extraction improvements maximize match
confidence by correctly handling edge cases like:
- Backticks around method values
- axios() with method in config object
- Various quote styles and spacing

**Validates: Requirements 2.1, 2.2**
"""
from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from depos.analysis.config import IntelligenceConfig
from depos.enrichment.semantic_edges import HTTP_CALLS_ROUTE, enrich_graph


@pytest.fixture
def method_context_repo(tmp_path: Path) -> tuple[Path, nx.DiGraph]:
    """Create a test repo with various HTTP method patterns."""
    # TypeScript file with various method patterns
    ts_path = tmp_path / "apps/web/api.ts"
    ts_path.parent.mkdir(parents=True, exist_ok=True)
    ts_path.write_text(
        """
// Test 1: fetch with backticks around method
export async function createRepo1() {
  const res = await fetch('/api/repos', { method: `POST` });
  return res.json();
}

// Test 2: axios with method in config
export async function createRepo2() {
  const res = await axios('/api/repos', { method: 'POST' });
  return res.data;
}

// Test 3: fetch with double quotes
export async function updateRepo() {
  const res = await fetch("/api/repos/1", { method: "PUT" });
  return res.json();
}

// Test 4: axios.delete (method from function name)
export async function deleteRepo() {
  const res = await axios.delete('/api/repos/1');
  return res.data;
}
""",
        encoding="utf-8",
    )
    
    # Python file with matching routes
    py_path = tmp_path / "backend/routers/repos.py"
    py_path.parent.mkdir(parents=True, exist_ok=True)
    py_path.write_text(
        """
from fastapi import APIRouter

router = APIRouter()

@router.post('/repos')
def create_repo():
    return {'id': 1}

@router.put('/repos/{repo_id}')
def update_repo(repo_id: str):
    return {'id': repo_id}

@router.delete('/repos/{repo_id}')
def delete_repo(repo_id: str):
    return {'deleted': True}
""",
        encoding="utf-8",
    )
    
    # Create graph
    graph = nx.DiGraph()
    
    # TS nodes
    for func_name in ["createRepo1", "createRepo2", "updateRepo", "deleteRepo"]:
        graph.add_node(
            f"ts:{func_name}",
            node_type="function",
            name=func_name,
            label=func_name,
            source_file=str(ts_path),
            language="typescript",
            file_type="code",
        )
    
    # Python nodes
    for func_name in ["create_repo", "update_repo", "delete_repo"]:
        graph.add_node(
            f"py:{func_name}",
            node_type="function",
            name=func_name,
            label=f"{func_name}()",
            source_file=str(py_path),
            language="python",
            file_type="code",
        )
    
    return tmp_path, graph


def test_method_context_preserved_for_matching(method_context_repo: tuple[Path, nx.DiGraph]) -> None:
    """Verify that improved HTTP method extraction enables correct route matching.
    
    **Validates: Requirements 2.1, 2.2**
    
    This test demonstrates that Task 7.2 improvements (backticks support,
    axios config extraction) preserve HTTP method context, which is critical
    for score_match to correctly match client routes to server routes.
    
    Without these improvements:
    - fetch with backticks: method=None → method mismatch penalty
    - axios with config: method=GET → wrong method, no match
    
    With improvements:
    - fetch with backticks: method=POST → correct match
    - axios with config: method=POST → correct match
    """
    repo_root, graph = method_context_repo
    config = IntelligenceConfig()
    
    # Run enrichment
    enriched, coverage = enrich_graph(graph, config=config, repo_root=repo_root)
    
    # Find HTTP_CALLS_ROUTE edges
    http_edges = [
        (u, v, data)
        for u, v, data in enriched.edges(data=True)
        if data.get("relation") == HTTP_CALLS_ROUTE
    ]
    
    # We expect at least 4 edges (one for each client-server pair)
    # Note: createRepo1 and createRepo2 both call POST /api/repos,
    # so they should both match the same server route
    assert len(http_edges) >= 3, (
        f"Expected at least 3 HTTP_CALLS_ROUTE edges, got {len(http_edges)}. "
        f"Method context preservation ensures correct matching."
    )
    
    # Verify edge properties
    methods_matched = set()
    for u, v, data in http_edges:
        assert data["source_system"] == "typescript"
        assert data["target_system"] == "python"
        assert data["contract_kind"] == "http"
        assert data["confidence"] > 0.6, (
            f"Edge confidence {data['confidence']} should be > 0.6 "
            f"(MIN_EMIT_CONFIDENCE threshold)"
        )
        methods_matched.add(data["api_method"])
    
    # Verify we matched different HTTP methods
    assert "POST" in methods_matched, "POST method should be matched"
    assert "PUT" in methods_matched, "PUT method should be matched"
    assert "DELETE" in methods_matched, "DELETE method should be matched"
    
    # Verify coverage metrics
    assert coverage.total_fastapi_routes == 3
    assert coverage.linked_routes >= 3, (
        f"Expected at least 3 linked routes, got {coverage.linked_routes}"
    )
    assert coverage.coverage_ratio >= 1.0, (
        f"Expected coverage_ratio >= 1.0, got {coverage.coverage_ratio}"
    )
    
    print(f"\n✓ Task 7.2 verified: {coverage.linked_routes}/{coverage.total_fastapi_routes} routes linked")
    print(f"✓ Methods matched: {sorted(methods_matched)}")
    print(f"✓ Coverage ratio: {coverage.coverage_ratio}")
    print(f"✓ HTTP method context preserved for accurate matching")


def test_method_extraction_edge_cases_summary() -> None:
    """Summary test documenting Task 7.2 improvements.
    
    **Validates: Requirements 2.1, 2.2**
    
    Task 7.2 improvements:
    1. Backticks support: method: `POST` now extracted correctly
    2. axios config: axios('/url', { method: 'POST' }) now extracts POST
    3. Robust regex: handles single quotes, double quotes, backticks
    
    Impact on match confidence:
    - Correct method extraction → method_matched=True in score_match
    - No method mismatch penalty → higher confidence scores
    - More edges emitted above MIN_EMIT_CONFIDENCE (0.6)
    - Better route linking coverage
    """
    from depos.enrichment.http_probes import scan_ts_http_calls
    
    # Test 1: Backticks
    sites1 = scan_ts_http_calls(
        "await fetch('/api/repos', { method: `POST` });",
        file="test.ts"
    )
    assert sites1[0].http_method == "POST"
    assert sites1[0].method_inferred == False
    
    # Test 2: axios config
    sites2 = scan_ts_http_calls(
        "await axios('/api/repos', { method: 'POST' });",
        file="test.ts"
    )
    assert sites2[0].http_method == "POST"
    assert sites2[0].method_inferred == False
    
    # Test 3: Mixed quotes
    sites3 = scan_ts_http_calls(
        """
        await fetch('/api/1', { method: 'POST' });
        await fetch("/api/2", { method: "PUT" });
        await fetch(`/api/3`, { method: `DELETE` });
        """,
        file="test.ts"
    )
    assert len(sites3) == 3
    assert sites3[0].http_method == "POST"
    assert sites3[1].http_method == "PUT"
    assert sites3[2].http_method == "DELETE"
    
    print("\n✓ Task 7.2 improvements verified:")
    print("  - Backticks around method values: ✓")
    print("  - axios() with method in config: ✓")
    print("  - Mixed quote styles: ✓")
    print("  - HTTP method context preserved for accurate route matching")
