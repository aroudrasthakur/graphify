r"""Bug Condition Exploration Test for Fix 5: Group C Taint Evidence Gating

**Validates: Requirements 1.11, 1.12, 2.11, 2.12**

This test demonstrates the bug where Group C candidates with no taint evidence
(empty taint_edges list) are sent to the LLM reasoner, producing hallucinated
findings. The _needs_llm_reasoning function in pipeline.py does not check
bundle.taint_edges_available for Group C candidates.

**CRITICAL**: This test is EXPECTED TO FAIL on unfixed code.
- Failure confirms the bug exists
- Success after fix confirms the bug is resolved

**Bug Description**:
When Group C candidates have no taint evidence (empty taint_edges list), the
system sends them to the LLM reasoner producing hallucinated findings. Group C
detectors emit candidates without taint chains and the system wastes LLM time
on candidates that cannot produce valid security findings.

**Root Cause**:
The `_needs_llm_reasoning` function in `depos/analysis/pipeline.py` does not
check `bundle.taint_edges_available` for Group C candidates (semantic_requirement="taint"),
allowing empty-taint candidates to reach the LLM and produce hallucinated findings.

**Example**:
- Group C candidate with empty taint_edges sent to LLM
- System produces hallucinated "SQL injection" finding
- Expected: Auto-gray-zoned without LLM call

**Expected Behavior After Fix**:
- System SHALL auto-gray-zone Group C candidates without taint evidence
- System SHALL gate LLM reasoning on non-empty taint chain presence
- Group C candidates with non-empty taint_edges SHALL continue to reach LLM
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from depos.analysis.pipeline import _needs_llm_reasoning
from depos.analysis.schemas import (
    Candidate,
    CandidateScore,
    ContextBundle,
    DetectorPayload,
    PackManifest,
    SeedType,
    TaintEdge,
)


@pytest.fixture
def group_c_candidate() -> Candidate:
    """Create a Group C candidate (semantic_requirement="taint").
    
    This simulates a candidate from a detector that requires taint analysis,
    such as sql-injection-approx or command-injection-approx.
    """
    return Candidate(
        candidate_id="cand_group_c_001",
        scope_id="py:vulnerable_function",
        seed_type=SeedType.interface_surface,
        language_path=["python"],
        score=CandidateScore(
            structural_centrality=0.5,
            seam_exposure=0.6,
            change_proximity=0.0,
            detector_confidence=0.7,
            evidence_quality=0.5,
            taint_chain_present=False,  # No taint chain found
            blast_radius_norm=0.3,
            composite=0.55,
        ),
        detector_payload=DetectorPayload(
            category="security",
            detector_name="sql-injection-approx",
            detector_version="1.0.0",
            pipeline_version="1.0.0",
            severity="high",
            raw={
                "sink_type": "sql_query",
                "source_type": "user_input",
            },
        ),
    )


@pytest.fixture
def bundle_without_taint() -> ContextBundle:
    """Create a bundle with no taint evidence (empty taint_edges list).
    
    This simulates the bug condition where a Group C candidate has no
    taint chain connecting source to sink.
    """
    return ContextBundle(
        bundle_id="bundle_001",
        candidate_id="cand_group_c_001",
        scope_id="py:vulnerable_function",
        scope_node_id="node:py:vulnerable_function",
        scope_text="def vulnerable_function(user_input):\n    query = f'SELECT * FROM users WHERE id = {user_input}'\n    execute_query(query)",
        scope_language="python",
        score_composite=0.55,
        cfg_available=True,
        dfg_available=True,
        taint_edges_available=False,  # No taint edges available
        taint_edges=[],  # Empty taint edges list - THIS IS THE BUG CONDITION
        callers=["node:caller_1"],
        callees=["node:callee_1"],
        caller_texts={"node:caller_1": "caller_function()"},
        callee_texts={"node:callee_1": "execute_query(query)"},
        pack_manifest=PackManifest(manifest_id="pack_001"),
    )


@pytest.fixture
def bundle_with_taint() -> ContextBundle:
    """Create a bundle with taint evidence (non-empty taint_edges list).
    
    This simulates the preservation case where a Group C candidate has a
    valid taint chain and should reach the LLM.
    """
    return ContextBundle(
        bundle_id="bundle_002",
        candidate_id="cand_group_c_002",
        scope_id="py:vulnerable_function",
        scope_node_id="node:py:vulnerable_function",
        scope_text="def vulnerable_function(user_input):\n    query = f'SELECT * FROM users WHERE id = {user_input}'\n    execute_query(query)",
        scope_language="python",
        score_composite=0.55,
        cfg_available=True,
        dfg_available=True,
        taint_edges_available=True,  # Taint edges available
        taint_edges=[  # Non-empty taint edges list
            TaintEdge(
                source_node="node:user_input",
                sink_node="node:sql_query",
                intermediate_path=["node:user_input", "node:vulnerable_function", "node:sql_query"],
                scope="py:vulnerable_function",
            )
        ],
        callers=["node:caller_1"],
        callees=["node:callee_1"],
        caller_texts={"node:caller_1": "caller_function()"},
        callee_texts={"node:callee_1": "execute_query(query)"},
        pack_manifest=PackManifest(manifest_id="pack_002"),
    )


@pytest.fixture
def group_c_detector_spec() -> SimpleNamespace:
    """Create a Group C detector spec (semantic_requirement="taint")."""
    return SimpleNamespace(
        name="sql-injection-approx",
        version="1.0.0",
        requires_reasoner=True,
        semantic_requirement="taint",  # Group C detector
    )


def test_bug_condition_group_c_no_taint_sent_to_llm(
    group_c_candidate: Candidate,
    bundle_without_taint: ContextBundle,
    group_c_detector_spec: SimpleNamespace,
) -> None:
    """Property 1: Bug Condition - Group C Hallucinated Findings
    
    **Validates: Requirements 1.11, 1.12, 2.11, 2.12**
    
    Test that Group C candidates with empty taint_edges are auto-gray-zoned
    without LLM call.
    
    **EXPECTED OUTCOME ON UNFIXED CODE**: Test FAILS
    - This is CORRECT - it proves the bug exists
    - _needs_llm_reasoning returns True despite empty taint_edges
    - Candidate is sent to LLM, producing hallucinated findings
    
    **EXPECTED OUTCOME AFTER FIX**: Test PASSES
    - _needs_llm_reasoning checks bundle.taint_edges_available
    - Returns False when taint evidence is missing
    - Candidate is auto-gray-zoned without LLM call
    
    **Counterexample**: Group C candidate with no taint sent to LLM,
    produced hallucinated finding.
    """
    # Verify the bug condition: Group C candidate with no taint evidence
    assert group_c_detector_spec.semantic_requirement == "taint", "Must be Group C detector"
    assert group_c_detector_spec.requires_reasoner is True, "Must require reasoner"
    assert bundle_without_taint.taint_edges_available is False, "Must have no taint available"
    assert len(bundle_without_taint.taint_edges) == 0, "Must have empty taint_edges list"
    
    # Call _needs_llm_reasoning
    # On unfixed code, this will return True (bug - sends to LLM)
    # After fix, this should return False (auto-gray-zone)
    needs_llm = _needs_llm_reasoning(
        group_c_candidate,
        bundle_without_taint,
        detector_spec=group_c_detector_spec,
    )
    
    # BUG ASSERTION: On unfixed code, needs_llm will be True
    # After fix, this should be False
    assert needs_llm is False, (
        f"Bug confirmed: _needs_llm_reasoning returned True for Group C candidate "
        f"with empty taint_edges (taint_edges_available={bundle_without_taint.taint_edges_available}, "
        f"len(taint_edges)={len(bundle_without_taint.taint_edges)}). "
        f"Expected: False (auto-gray-zone without LLM call). "
        f"This causes the system to send candidates without taint evidence to the LLM, "
        f"producing hallucinated findings like 'SQL injection' when no actual taint chain exists. "
        f"The _needs_llm_reasoning function must check bundle.taint_edges_available "
        f"and len(bundle.taint_edges) > 0 for Group C candidates (semantic_requirement='taint')."
    )
    
    print(f"\n✓ Bug fix verified: Group C candidate with no taint auto-gray-zoned")
    print(f"✓ taint_edges_available: {bundle_without_taint.taint_edges_available}")
    print(f"✓ len(taint_edges): {len(bundle_without_taint.taint_edges)}")
    print(f"✓ needs_llm_reasoning: {needs_llm}")


def test_preservation_group_c_with_taint_reaches_llm(
    group_c_candidate: Candidate,
    bundle_with_taint: ContextBundle,
    group_c_detector_spec: SimpleNamespace,
) -> None:
    """Property 2: Preservation - Group C with Taint Reaches LLM
    
    **Validates: Requirements 3.7**
    
    Test that Group C candidates with non-empty taint_edges continue to
    reach the LLM reasoner for analysis.
    
    This preservation test ensures the fix doesn't break the normal case where
    Group C candidates have valid taint chains and should be analyzed by the LLM.
    
    **EXPECTED OUTCOME**: Test PASSES (both before and after fix)
    - Group C candidates with taint evidence continue to reach LLM
    - Valid taint chains are analyzed for security findings
    - No regression in normal operation
    """
    # Verify the preservation condition: Group C candidate with taint evidence
    assert group_c_detector_spec.semantic_requirement == "taint", "Must be Group C detector"
    assert group_c_detector_spec.requires_reasoner is True, "Must require reasoner"
    assert bundle_with_taint.taint_edges_available is True, "Must have taint available"
    assert len(bundle_with_taint.taint_edges) > 0, "Must have non-empty taint_edges list"
    
    # Call _needs_llm_reasoning
    # This should return True (send to LLM) both before and after fix
    needs_llm = _needs_llm_reasoning(
        group_c_candidate,
        bundle_with_taint,
        detector_spec=group_c_detector_spec,
    )
    
    # PRESERVATION ASSERTION: Should be True both before and after fix
    assert needs_llm is True, (
        f"Preservation check failed: _needs_llm_reasoning returned False for Group C candidate "
        f"with valid taint evidence (taint_edges_available={bundle_with_taint.taint_edges_available}, "
        f"len(taint_edges)={len(bundle_with_taint.taint_edges)}). "
        f"Expected: True (send to LLM for analysis). "
        f"The fix should only gate candidates WITHOUT taint evidence, not those WITH taint evidence."
    )
    
    print(f"\n✓ Preservation verified: Group C candidate with taint reaches LLM")
    print(f"✓ taint_edges_available: {bundle_with_taint.taint_edges_available}")
    print(f"✓ len(taint_edges): {len(bundle_with_taint.taint_edges)}")
    print(f"✓ needs_llm_reasoning: {needs_llm}")


def test_preservation_group_a_unaffected(
    bundle_without_taint: ContextBundle,
) -> None:
    """Property 2: Preservation - Group A Candidates Unaffected
    
    **Validates: Requirements 3.2**
    
    Test that Group A candidates (semantic_requirement=None) continue to
    process through the reasoner without taint evidence requirements.
    
    Group A detectors don't require semantic layers and should not be gated
    by taint evidence checks.
    
    **EXPECTED OUTCOME**: Test PASSES (both before and after fix)
    - Group A candidates process without taint requirements
    - No taint evidence check applied to Group A
    - No regression in Group A operation
    """
    # Create a Group A candidate (semantic_requirement=None)
    group_a_candidate = Candidate(
        candidate_id="cand_group_a_001",
        scope_id="py:suspicious_function",
        seed_type=SeedType.graph_anomaly,
        language_path=["python"],
        score=CandidateScore(
            structural_centrality=0.7,
            seam_exposure=0.8,
            change_proximity=0.0,
            detector_confidence=0.6,
            evidence_quality=0.5,
            taint_chain_present=False,
            blast_radius_norm=0.4,
            composite=0.65,
        ),
        detector_payload=DetectorPayload(
            category="structural",
            detector_name="graph-anomaly",
            detector_version="1.0.0",
            pipeline_version="1.0.0",
            severity="medium",
            raw={
                "anomaly": "orphan_interface_surface",
            },
        ),
    )
    
    # Create a Group A detector spec (semantic_requirement=None)
    group_a_detector_spec = SimpleNamespace(
        name="graph-anomaly",
        version="1.0.0",
        requires_reasoner=True,
        semantic_requirement=None,  # Group A detector
    )
    
    # Verify Group A detector
    assert group_a_detector_spec.semantic_requirement is None, "Must be Group A detector"
    assert group_a_detector_spec.requires_reasoner is True, "Must require reasoner"
    
    # Call _needs_llm_reasoning
    # Group A should not be affected by taint evidence checks
    needs_llm = _needs_llm_reasoning(
        group_a_candidate,
        bundle_without_taint,
        detector_spec=group_a_detector_spec,
    )
    
    # PRESERVATION ASSERTION: Group A should process normally
    # The result depends on other gates (seam_exposure, composite score, etc.)
    # but NOT on taint evidence
    # In this case, with high seam_exposure (0.8) and composite (0.65), it should return True
    assert needs_llm is True, (
        f"Preservation check failed: _needs_llm_reasoning returned False for Group A candidate "
        f"with high seam_exposure ({group_a_candidate.score.seam_exposure}) and "
        f"composite score ({group_a_candidate.score.composite}). "
        f"Expected: True (Group A should not be gated by taint evidence). "
        f"The fix should only apply taint evidence checks to Group C candidates, not Group A."
    )
    
    print(f"\n✓ Preservation verified: Group A candidate processes without taint requirements")
    print(f"✓ semantic_requirement: {group_a_detector_spec.semantic_requirement}")
    print(f"✓ needs_llm_reasoning: {needs_llm}")


def test_preservation_group_b_unaffected(
    bundle_without_taint: ContextBundle,
) -> None:
    """Property 2: Preservation - Group B Candidates Unaffected
    
    **Validates: Requirements 3.2**
    
    Test that Group B candidates (semantic_requirement="cfg") continue to
    process through the reasoner without taint evidence requirements.
    
    Group B detectors require CFG but not taint analysis, and should not be
    gated by taint evidence checks.
    
    **EXPECTED OUTCOME**: Test PASSES (both before and after fix)
    - Group B candidates process without taint requirements
    - No taint evidence check applied to Group B
    - No regression in Group B operation
    """
    # Create a Group B candidate (semantic_requirement="cfg")
    group_b_candidate = Candidate(
        candidate_id="cand_group_b_001",
        scope_id="py:loop_function",
        seed_type=SeedType.interface_surface,
        language_path=["python"],
        score=CandidateScore(
            structural_centrality=0.6,
            seam_exposure=0.7,
            change_proximity=0.0,
            detector_confidence=0.8,
            evidence_quality=0.6,
            taint_chain_present=False,
            blast_radius_norm=0.3,
            composite=0.60,
        ),
        detector_payload=DetectorPayload(
            category="logic",
            detector_name="infinite-loop",
            detector_version="1.0.0",
            pipeline_version="1.0.0",
            severity="medium",
            raw={
                "loop_type": "while",
                "exit_condition": "missing",
            },
        ),
    )
    
    # Create a Group B detector spec (semantic_requirement="cfg")
    group_b_detector_spec = SimpleNamespace(
        name="infinite-loop",
        version="1.0.0",
        requires_reasoner=True,
        semantic_requirement="cfg",  # Group B detector
    )
    
    # Verify Group B detector
    assert group_b_detector_spec.semantic_requirement == "cfg", "Must be Group B detector"
    assert group_b_detector_spec.requires_reasoner is True, "Must require reasoner"
    
    # Call _needs_llm_reasoning
    # Group B should not be affected by taint evidence checks
    needs_llm = _needs_llm_reasoning(
        group_b_candidate,
        bundle_without_taint,
        detector_spec=group_b_detector_spec,
    )
    
    # PRESERVATION ASSERTION: Group B should process normally
    # The result depends on other gates (seam_exposure, composite score, etc.)
    # but NOT on taint evidence
    # In this case, with high seam_exposure (0.7) and composite (0.60), it should return True
    assert needs_llm is True, (
        f"Preservation check failed: _needs_llm_reasoning returned False for Group B candidate "
        f"with high seam_exposure ({group_b_candidate.score.seam_exposure}) and "
        f"composite score ({group_b_candidate.score.composite}). "
        f"Expected: True (Group B should not be gated by taint evidence). "
        f"The fix should only apply taint evidence checks to Group C candidates, not Group B."
    )
    
    print(f"\n✓ Preservation verified: Group B candidate processes without taint requirements")
    print(f"✓ semantic_requirement: {group_b_detector_spec.semantic_requirement}")
    print(f"✓ needs_llm_reasoning: {needs_llm}")
