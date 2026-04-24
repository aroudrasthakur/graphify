r"""Bug Condition Exploration Test for Fix 4: Graph-Anomaly Noise Suppression

**Validates: Requirements 1.9, 1.10, 2.9, 2.10**

This test demonstrates the bug where the graph-anomaly detector emits
structural placeholder candidates without checking run_metadata.low_stitcher_coverage,
flooding the candidate budget with high-noise candidates when Module 1 fails
to link routes.

**CRITICAL**: This test is EXPECTED TO FAIL on unfixed code.
- Failure confirms the bug exists
- Success after fix confirms the bug is resolved

**Bug Description**:
When stitcher coverage is low (<20%) in full_repo_scan mode, the system emits
graph-anomaly structural placeholders that flood the candidate budget. The
graph-anomaly detector runs without checking coverage and produces high-noise
candidates with no actionable signal.

**Root Cause**:
The graph-anomaly detector in `depos/analysis/detectors/builtin/graph_anomaly.py`
calls `_graph_anomaly_candidates(graph, mode)` without checking
`graph.graph["run_metadata"]["low_stitcher_coverage"]`. This causes emission
even when Module 1 (stitcher) has failed to link routes.

**Example**:
- Full repo scan with 5% stitcher coverage
- System emits 200+ graph-anomaly candidates
- Expected: 0 graph-anomaly candidates emitted when coverage < 20%

**Expected Behavior After Fix**:
- System SHALL suppress graph-anomaly detector emission when coverage < 20%
- System SHALL skip candidate emission when config.low_stitcher_coverage_threshold is not met
- Adequate-coverage runs (>=20%) SHALL continue to emit graph-anomaly candidates normally
"""
from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors.builtin.graph_anomaly import run as graph_anomaly_run
from depos.analysis.schemas import AnalysisMode


@pytest.fixture
def low_coverage_graph(tmp_path: Path) -> nx.DiGraph:
    """Create a graph with low stitcher coverage (<20%) that triggers the bug.
    
    This simulates a full_repo_scan where Module 1 (stitcher) failed to link
    routes, resulting in many orphaned route nodes and unmatched HTTP clients.
    """
    graph = nx.DiGraph()
    
    # Create 20 FastAPI routes without HTTP_CALLS_ROUTE edges (orphaned)
    # This simulates the stitcher failing to link routes
    for i in range(20):
        route_id = f"py:route_{i}"
        graph.add_node(
            route_id,
            node_type="function",
            name=f"route_{i}",
            label=f"route_{i}()",
            source_file=str(tmp_path / f"backend/routes_{i}.py"),
            language="python",
            file_type="code",
            route_pattern=f"/api/resource_{i}",
            http_method="GET",
            is_public_route=True,
        )
    
    # Create 20 TypeScript HTTP clients without HTTP_CALLS_ROUTE edges (unmatched)
    for i in range(20):
        client_id = f"ts:client_{i}"
        graph.add_node(
            client_id,
            node_type="function",
            name=f"client_{i}",
            label=f"client_{i}",
            source_file=str(tmp_path / f"apps/web/client_{i}.tsx"),
            language="typescript",
            file_type="code",
            http_call_sites=[
                {
                    "url_literal": f"/api/resource_{i}",
                    "method": "GET",
                }
            ],
        )
    
    # Simulate low stitcher coverage (5%) - only 1 out of 20 routes linked
    # Add run_metadata to indicate low coverage
    graph.graph["run_metadata"] = {
        "low_stitcher_coverage": True,
        "coverage": {
            "total_fastapi_routes": 20,
            "linked_routes": 1,
            "unlinked_routes": 19,
            "coverage_ratio": 0.05,
            "low_coverage": True,
        },
    }
    
    return graph


def test_bug_condition_graph_anomaly_noise_in_low_coverage(low_coverage_graph: nx.DiGraph) -> None:
    """Property 1: Bug Condition - Graph-Anomaly Noise in Low Coverage Runs
    
    **Validates: Requirements 1.9, 1.10, 2.9, 2.10**
    
    Test that graph-anomaly detector emits 0 candidates when coverage < 20%
    in full_repo_scan mode.
    
    **EXPECTED OUTCOME ON UNFIXED CODE**: Test FAILS
    - This is CORRECT - it proves the bug exists
    - Detector emits 200+ candidates despite low coverage
    - Candidates flood the budget with high-noise structural placeholders
    
    **EXPECTED OUTCOME AFTER FIX**: Test PASSES
    - Detector checks run_metadata.low_stitcher_coverage
    - 0 candidates emitted when coverage < 20%
    - Adequate-coverage runs (>=20%) continue to emit normally
    
    **Counterexample**: Full repo scan with 5% stitcher coverage emits
    200+ graph-anomaly candidates instead of 0.
    """
    config = IntelligenceConfig()
    mode = AnalysisMode.full_repo_scan
    
    # Verify the graph has low coverage set
    assert low_coverage_graph.graph["run_metadata"]["low_stitcher_coverage"] is True
    assert low_coverage_graph.graph["run_metadata"]["coverage"]["coverage_ratio"] == 0.05
    
    # Run the graph-anomaly detector
    # On unfixed code, this will emit many candidates despite low coverage
    candidates = graph_anomaly_run(
        graph=low_coverage_graph,
        manifest=None,
        mode=mode,
        config=config,
        ctx=None,
    )
    
    # Count different anomaly types
    orphan_routes = sum(1 for c in candidates if c.detector_payload.raw.get("anomaly") == "fastapi_route_without_client_calls")
    unmatched_clients = sum(1 for c in candidates if c.detector_payload.raw.get("anomaly") == "unmatched_http_client_call")
    orphan_surfaces = sum(1 for c in candidates if c.detector_payload.raw.get("anomaly") == "orphan_interface_surface")
    
    # BUG ASSERTION: On unfixed code, candidates will be emitted despite low coverage
    # After fix, this should be 0
    assert len(candidates) == 0, (
        f"Bug confirmed: Graph-anomaly detector emitted {len(candidates)} candidates "
        f"despite low stitcher coverage (5% < 20% threshold). "
        f"Breakdown: {orphan_routes} orphan routes, {unmatched_clients} unmatched clients, "
        f"{orphan_surfaces} orphan surfaces. "
        f"Expected: 0 candidates emitted when low_stitcher_coverage=True. "
        f"This floods the candidate budget with high-noise structural placeholders "
        f"when Module 1 (stitcher) fails to link routes."
    )
    
    print(f"\n✓ Bug fix verified: 0 candidates emitted in low-coverage full_repo_scan")
    print(f"✓ Coverage: {low_coverage_graph.graph['run_metadata']['coverage']['coverage_ratio']*100:.1f}%")
    print(f"✓ Noise suppression working correctly")


def test_preservation_adequate_coverage_emits_candidates(tmp_path: Path) -> None:
    """Property 2: Preservation - Adequate Coverage Continues to Emit
    
    **Validates: Requirements 3.1**
    
    Test that when stitcher coverage is adequate (>=20%), the graph-anomaly
    detector continues to emit candidates normally.
    
    This preservation test ensures the fix doesn't break the normal case where
    graph-anomaly candidates provide valuable signal.
    
    **EXPECTED OUTCOME**: Test PASSES (both before and after fix)
    - Adequate coverage (>=20%) continues to emit candidates
    - Graph-anomaly detector provides structural signal
    - No regression in normal operation
    """
    graph = nx.DiGraph()
    
    # Create 10 FastAPI routes, 8 linked (80% coverage)
    for i in range(10):
        route_id = f"py:route_{i}"
        graph.add_node(
            route_id,
            node_type="function",
            name=f"route_{i}",
            label=f"route_{i}()",
            source_file=str(tmp_path / f"backend/routes_{i}.py"),
            language="python",
            file_type="code",
            route_pattern=f"/api/resource_{i}",
            http_method="GET",
            is_public_route=True,
        )
    
    # Create 2 unmatched HTTP clients (to generate some graph-anomaly candidates)
    for i in range(2):
        client_id = f"ts:client_{i}"
        graph.add_node(
            client_id,
            node_type="function",
            name=f"client_{i}",
            label=f"client_{i}",
            source_file=str(tmp_path / f"apps/web/client_{i}.tsx"),
            language="typescript",
            file_type="code",
            http_call_sites=[
                {
                    "url_literal": f"/api/unmatched_{i}",
                    "method": "GET",
                }
            ],
        )
    
    # Simulate adequate stitcher coverage (80%)
    graph.graph["run_metadata"] = {
        "low_stitcher_coverage": False,
        "coverage": {
            "total_fastapi_routes": 10,
            "linked_routes": 8,
            "unlinked_routes": 2,
            "coverage_ratio": 0.80,
            "low_coverage": False,
        },
    }
    
    config = IntelligenceConfig()
    mode = AnalysisMode.full_repo_scan
    
    # Run the graph-anomaly detector
    candidates = graph_anomaly_run(
        graph=graph,
        manifest=None,
        mode=mode,
        config=config,
        ctx=None,
    )
    
    # With adequate coverage, candidates should be emitted
    # We expect at least the 2 unmatched clients to generate candidates
    assert len(candidates) > 0, (
        f"Preservation check failed: Expected candidates to be emitted with adequate coverage (80%). "
        f"Got {len(candidates)} candidates. "
        f"The fix should only suppress emission when coverage < 20%, not when coverage >= 20%."
    )
    
    # Verify we have unmatched client candidates
    unmatched_clients = [c for c in candidates if c.detector_payload.raw.get("anomaly") == "unmatched_http_client_call"]
    assert len(unmatched_clients) > 0, (
        "Expected unmatched HTTP client candidates to be emitted with adequate coverage"
    )
    
    print(f"\n✓ Preservation verified: {len(candidates)} candidates emitted with adequate coverage (80%)")
    print(f"✓ Graph-anomaly detector continues to provide structural signal")


def test_preservation_diff_aware_mode_unaffected(tmp_path: Path) -> None:
    """Property 2: Preservation - Diff-Aware Mode Unaffected by Coverage
    
    **Validates: Requirements 3.1**
    
    Test that in diff-aware mode, graph-anomaly candidates are emitted
    regardless of stitcher coverage. The coverage check should only apply
    to full_repo_scan mode.
    
    **EXPECTED OUTCOME**: Test PASSES (both before and after fix)
    - Diff-aware mode emits candidates regardless of coverage
    - Coverage check only applies to full_repo_scan mode
    - No regression in diff-aware operation
    """
    graph = nx.DiGraph()
    
    # Create a route without HTTP_CALLS_ROUTE edge
    route_id = "py:route_0"
    graph.add_node(
        route_id,
        node_type="function",
        name="route_0",
        label="route_0()",
        source_file=str(tmp_path / "backend/routes.py"),
        language="python",
        file_type="code",
        route_pattern="/api/resource",
        http_method="GET",
        is_public_route=True,
    )
    
    # Simulate low stitcher coverage (5%)
    # In diff-aware mode, this should NOT suppress emission
    graph.graph["run_metadata"] = {
        "low_stitcher_coverage": True,
        "coverage": {
            "total_fastapi_routes": 1,
            "linked_routes": 0,
            "unlinked_routes": 1,
            "coverage_ratio": 0.0,
            "low_coverage": True,
        },
    }
    
    config = IntelligenceConfig()
    mode = AnalysisMode.diff_aware
    
    # Run the graph-anomaly detector in diff-aware mode
    candidates = graph_anomaly_run(
        graph=graph,
        manifest=None,
        mode=mode,
        config=config,
        ctx=None,
    )
    
    # In diff-aware mode, candidates should be emitted even with low coverage
    assert len(candidates) > 0, (
        f"Preservation check failed: Expected candidates to be emitted in diff-aware mode "
        f"regardless of coverage. Got {len(candidates)} candidates. "
        f"The fix should only suppress emission in full_repo_scan mode, not diff-aware mode."
    )
    
    print(f"\n✓ Preservation verified: {len(candidates)} candidates emitted in diff-aware mode")
    print(f"✓ Coverage check correctly scoped to full_repo_scan mode only")
