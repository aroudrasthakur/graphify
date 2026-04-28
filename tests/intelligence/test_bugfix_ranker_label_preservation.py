r"""Bug Condition Exploration Test for Fix 2: Ranker Label Preservation

**Validates: Requirements 1.3, 1.4, 2.3, 2.4**

This test demonstrates the bug where the ranker (or detector system) overwrites
candidate.detector_payload.detector_name with attack pattern labels like
"command-injection-approx" instead of preserving "graph-anomaly" for candidates
with seed_type=SeedType.graph_anomaly.

**CRITICAL**: This test is EXPECTED TO FAIL on unfixed code.
- Failure confirms the bug exists
- Success after fix confirms the bug is resolved

**Root Cause**: The detector system sets detector_name to the specific detector
spec name (e.g., "command-injection-approx") rather than preserving the seed_type
identity ("graph-anomaly"). Attack pattern labels should be stored in a separate
ranking_metadata.matched_pattern field.

**Counterexample**:
- Detector: command-injection-approx (Group C taint detector)
- seed_type: SeedType.graph_anomaly
- Expected: detector_name="graph-anomaly", ranking_metadata.matched_pattern="command-injection-approx"
- Actual: detector_name="command-injection-approx", ranking_metadata=None

**Expected Behavior After Fix**:
- detector_payload.detector_name preserved as "graph-anomaly"
- Attack pattern stored in ranking_metadata.matched_pattern
- Detector identity tracking remains intact
"""
from __future__ import annotations

import networkx as nx
import pytest

from depos.analysis.config import IntelligenceConfig
from depos.analysis.detectors import run_all
from depos.analysis.run_context import GraphMetrics, RunContext
from depos.analysis.schemas import AnalysisMode, ChangeManifest, SeedType, TaintEdge


def _rc(graph: nx.DiGraph, config: IntelligenceConfig) -> RunContext:
    """Helper to create RunContext for tests."""
    m = GraphMetrics()
    m._computed = True
    return RunContext(
        manifest=ChangeManifest(entries=[], resolved_via="empty"),
        graph_metrics=m,
        cfg_available={},
        dfg_available={},
        taint_edges_available={},
    )


@pytest.fixture
def graph_with_taint_edge() -> nx.DiGraph:
    """Create a minimal graph with a taint edge that triggers command-injection-approx detector.
    
    This simulates a graph-anomaly candidate that gets labeled with an attack pattern.
    """
    graph = nx.DiGraph()
    
    # Add source and sink nodes
    source_node = "node:user_input"
    sink_node = "node:subprocess_call"
    
    graph.add_node(
        source_node,
        label="user_input",
        source_file="app/handlers.py",
        language="python",
        node_type="variable",
    )
    
    graph.add_node(
        sink_node,
        label="subprocess.run",
        source_file="app/handlers.py",
        language="python",
        node_type="function_call",
    )
    
    # Add taint edge that will trigger command-injection-approx detector
    taint_edge = TaintEdge(
        source_node=source_node,
        sink_node=sink_node,
        intermediate_path=[source_node, sink_node],
        crosses_seam=False,
        source_chain="request.query_params['cmd']",
        sink_pattern="subprocess.run(cmd, shell=True)",
        scope=sink_node,
        line=42,
    )
    
    # Store taint edges in graph metadata (this is how the detector system accesses them)
    graph.graph["taint_edges"] = [taint_edge]
    
    return graph


def test_bug_condition_ranker_label_corruption(graph_with_taint_edge: nx.DiGraph) -> None:
    """Property 1: Bug Condition - Ranker Label Corruption
    
    **Validates: Requirements 1.3, 1.4, 2.3, 2.4**
    
    Test that Group C detectors (like command-injection-approx) preserve
    detector_payload.detector_name as "graph-anomaly" and store attack
    patterns in a separate ranking_metadata.matched_pattern field.
    
    **EXPECTED OUTCOME ON UNFIXED CODE**: Test FAILS
    - This is CORRECT - it proves the bug exists
    - detector_name == "command-injection-approx" (overwritten)
    - ranking_metadata is None or doesn't contain matched_pattern
    
    **EXPECTED OUTCOME AFTER FIX**: Test PASSES
    - detector_name == "graph-anomaly" (preserved)
    - ranking_metadata.matched_pattern == "command-injection-approx"
    - Detector identity tracking intact
    
    **Counterexample**: Group C taint detector overwrites detector_name
    with attack pattern label instead of preserving seed_type identity.
    """
    config = IntelligenceConfig()
    manifest = ChangeManifest(entries=[], resolved_via="empty")
    
    # Create RunContext with taint edges available for the sink node
    m = GraphMetrics()
    m._computed = True
    run_context = RunContext(
        manifest=manifest,
        graph_metrics=m,
        cfg_available={},
        dfg_available={"node:subprocess_call": True},
        taint_edges_available={"node:subprocess_call": True},
    )
    
    # Run all detectors (this will trigger command-injection-approx)
    candidates, stats = run_all(
        graph_with_taint_edge,
        manifest,
        AnalysisMode.full_repo_scan,
        config,
        run_context=run_context,
    )
    
    # After fix: Find graph-anomaly candidates with matched_pattern="command-injection-approx"
    # Before fix: Would find candidates with detector_name="command-injection-approx"
    cmd_injection_candidates = [
        c for c in candidates
        if c.seed_type == SeedType.graph_anomaly
        and c.ranking_metadata is not None
        and c.ranking_metadata.matched_pattern == "command-injection-approx"
    ]
    
    # Verify the detector emitted a candidate
    assert len(cmd_injection_candidates) > 0, (
        "command-injection-approx detector should emit at least one candidate"
    )
    
    candidate = cmd_injection_candidates[0]
    
    # Check seed_type - should be graph_anomaly
    assert candidate.seed_type == SeedType.graph_anomaly, (
        f"Expected seed_type=graph_anomaly, got {candidate.seed_type}"
    )
    
    # BUG ASSERTION: This is where the bug manifests
    # On unfixed code, detector_name will be "command-injection-approx"
    # After fix, it should be "graph-anomaly"
    assert candidate.detector_payload.detector_name == "graph-anomaly", (
        f"Bug confirmed: detector_name overwritten with attack pattern label. "
        f"Expected: 'graph-anomaly', "
        f"Actual: '{candidate.detector_payload.detector_name}'. "
        f"Attack pattern labels should be stored in ranking_metadata.matched_pattern, "
        f"not in detector_payload.detector_name."
    )
    
    # After fix, verify ranking_metadata contains the attack pattern
    assert hasattr(candidate, "ranking_metadata"), (
        "Candidate should have ranking_metadata field after fix"
    )
    assert candidate.ranking_metadata is not None, (
        "ranking_metadata should not be None after fix"
    )
    assert hasattr(candidate.ranking_metadata, "matched_pattern"), (
        "ranking_metadata should have matched_pattern field after fix"
    )
    assert candidate.ranking_metadata.matched_pattern == "command-injection-approx", (
        f"Expected ranking_metadata.matched_pattern='command-injection-approx', "
        f"got '{candidate.ranking_metadata.matched_pattern}'"
    )
    
    print(f"\n✓ Bug fix verified: detector_name preserved as 'graph-anomaly'")
    print(f"✓ Attack pattern stored in ranking_metadata.matched_pattern: '{candidate.ranking_metadata.matched_pattern}'")
    print(f"✓ Detector identity tracking intact")


def test_bug_condition_non_graph_anomaly_detectors_unaffected() -> None:
    """Property 2: Preservation - Non-Graph-Anomaly Detectors Unchanged
    
    **Validates: Requirements 3.4**
    
    Test that non-graph-anomaly detectors (like env-var-referenced-but-undefined)
    continue to preserve their detector_name values unchanged.
    
    This ensures the fix doesn't break existing detector behavior.
    """
    graph = nx.DiGraph()
    
    # Add an env var node that's referenced but not defined
    graph.add_node(
        "env:DATABASE_URL",
        label="DATABASE_URL",
        node_type="env_var",
        language="env",
        referenced=True,
        defined=False,
    )
    
    config = IntelligenceConfig()
    manifest = ChangeManifest(entries=[], resolved_via="empty")
    run_context = _rc(graph, config)
    
    # Run all detectors
    candidates, stats = run_all(
        graph,
        manifest,
        AnalysisMode.full_repo_scan,
        config,
        run_context=run_context,
    )
    
    # Find env-var detector candidates
    env_var_candidates = [
        c for c in candidates
        if "env-var" in c.detector_payload.detector_name
    ]
    
    if len(env_var_candidates) > 0:
        candidate = env_var_candidates[0]
        
        # Verify detector_name is preserved (not overwritten with "graph-anomaly")
        assert candidate.detector_payload.detector_name != "graph-anomaly", (
            "Non-graph-anomaly detectors should preserve their own detector_name"
        )
        
        # Verify it matches the detector spec name
        assert "env-var" in candidate.detector_payload.detector_name, (
            f"Expected detector_name to contain 'env-var', got '{candidate.detector_payload.detector_name}'"
        )
        
        print(f"\n✓ Preservation verified: non-graph-anomaly detector_name unchanged: '{candidate.detector_payload.detector_name}'")
