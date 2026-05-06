from __future__ import annotations

from depos.analysis.config import IntelligenceConfig
from depos.analysis.schemas import (
    AnalysisMode,
    BundleNodeFact,
    Candidate,
    CandidateScore,
    ContextBundle,
    DetectorPayload,
    ModeAFinding,
    PackManifest,
    ReasonerMode,
    SeamEdge,
    SeedType,
    TaintEdge,
    VerifierOutcome,
)
from depos.analysis.verifier import verify


def _candidate(
    *,
    detector_name: str,
    taint_chain_present: bool = False,
) -> Candidate:
    return Candidate(
        candidate_id=f"cand_{detector_name}",
        scope_id="node:scope",
        seed_type=SeedType.graph_anomaly,
        analysis_mode=AnalysisMode.full_repo_scan,
        score=CandidateScore(taint_chain_present=taint_chain_present, blast_radius_norm=0.2),
        detector_payload=DetectorPayload(
            detector_name=detector_name,
            detector_version="0.1.0",
            pipeline_version="2.0.0",
            severity="high",
        ),
        seam_edges=[
            SeamEdge(
                edge_id="edge:scope->sink",
                source="scope",
                target="sink",
                relation="SEAM_HTTP",
            )
        ],
    )


def _bundle(
    *,
    cfg_available: bool = False,
    cfg_summary: str | None = None,
    taint_edges: list[TaintEdge] | None = None,
    node_ids: list[str] | None = None,
) -> ContextBundle:
    ids = node_ids or ["scope", "source", "sink"]
    return ContextBundle(
        bundle_id="bundle_1",
        candidate_id="cand_x",
        scope_id="node:scope",
        scope_node_id="scope",
        scope_text="async function handler(req) { return sink(req.userInput) }",
        scope_language="typescript",
        cfg_available=cfg_available,
        dfg_available=bool(taint_edges),
        taint_edges_available=bool(taint_edges),
        cfg_summary=cfg_summary,
        taint_edges=taint_edges or [],
        node_facts={node_id: BundleNodeFact(node_id=node_id) for node_id in ids},
        pack_manifest=PackManifest(manifest_id="pack_1"),
        is_articulation_point=True,
        pagerank_percentile=0.42,
    )


def _mode_a(
    *,
    bug_type: str,
    description: str,
    affected_path: list[str] | None = None,
    confidence: float = 0.91,
) -> ModeAFinding:
    return ModeAFinding(
        bug_type=bug_type,
        description=description,
        affected_path=affected_path or [],
        confidence=confidence,
    )


def test_security_rule_confirms_with_taint_chain_and_bundle_evidence() -> None:
    candidate = _candidate(detector_name="sql-injection-approx", taint_chain_present=True)
    bundle = _bundle(
        taint_edges=[
            TaintEdge(
                source_node="source",
                sink_node="sink",
                intermediate_path=["source", "scope", "sink"],
                sink_pattern="sql query builder",
                scope="scope",
            )
        ]
    )
    finding = _mode_a(
        bug_type="sql-injection",
        description="Potential SQL injection along [node:source] to [node:sink]",
        affected_path=["source", "sink"],
    )

    audit, verified = verify(
        candidate=candidate,
        bundle=bundle,
        mode=ReasonerMode.A,
        finding=finding,
        config=IntelligenceConfig(),
        full_repo_scan=True,
    )

    assert audit.verifier_outcome == VerifierOutcome.partially_confirmed
    assert verified.verifier_outcome == VerifierOutcome.partially_confirmed
    assert verified.partially_confirmed_caveat
    assert audit.failed_rule == ""


def test_security_rule_unconfirmed_when_taint_chain_score_missing() -> None:
    candidate = _candidate(detector_name="sql-injection-approx", taint_chain_present=False)
    bundle = _bundle(
        taint_edges=[
            TaintEdge(
                source_node="source",
                sink_node="sink",
                intermediate_path=["source", "scope", "sink"],
                sink_pattern="sql query builder",
                scope="scope",
            )
        ]
    )
    finding = _mode_a(
        bug_type="sql-injection",
        description="Potential SQL injection along [node:source] to [node:sink]",
        affected_path=["source", "sink"],
    )

    audit, verified = verify(
        candidate=candidate,
        bundle=bundle,
        mode=ReasonerMode.A,
        finding=finding,
        config=IntelligenceConfig(),
        full_repo_scan=True,
    )

    assert audit.verifier_outcome == VerifierOutcome.unconfirmed
    assert verified.verifier_outcome == VerifierOutcome.unconfirmed
    assert audit.failed_rule == "taint_chain_present"
    assert "taint_chain_present" in audit.missing_evidence


def test_correctness_rule_confirms_with_cfg_summary() -> None:
    candidate = _candidate(detector_name="null-dereference-approx")
    bundle = _bundle(cfg_available=True, cfg_summary="entry -> nullable call -> dereference -> exit")
    finding = _mode_a(
        bug_type="null-dereference",
        description="Null dereference at [node:scope]",
        affected_path=["scope"],
    )

    audit, verified = verify(
        candidate=candidate,
        bundle=bundle,
        mode=ReasonerMode.A,
        finding=finding,
        config=IntelligenceConfig(),
        full_repo_scan=True,
    )

    assert audit.verifier_outcome == VerifierOutcome.partially_confirmed
    assert verified.verifier_outcome == VerifierOutcome.partially_confirmed
    assert verified.partially_confirmed_caveat


def test_correctness_rule_auto_grayzones_before_rule_when_cfg_missing() -> None:
    candidate = _candidate(detector_name="null-dereference-approx")
    bundle = _bundle(cfg_available=False, cfg_summary=None)
    finding = _mode_a(
        bug_type="null-dereference",
        description="Null dereference at [node:scope]",
        affected_path=["scope"],
    )

    audit, verified = verify(
        candidate=candidate,
        bundle=bundle,
        mode=ReasonerMode.A,
        finding=finding,
        config=IntelligenceConfig(),
        full_repo_scan=True,
    )

    assert audit.verifier_outcome == VerifierOutcome.partially_confirmed
    assert verified.verifier_outcome == VerifierOutcome.partially_confirmed
    assert audit.failed_rule == "cfg_available is False"


def test_global_uncited_auto_grayzones_regardless_of_category() -> None:
    candidate = _candidate(detector_name="null-dereference-approx")
    bundle = _bundle(cfg_available=True, cfg_summary="entry -> branch -> exit", node_ids=["scope"])
    finding = _mode_a(
        bug_type="null-dereference",
        description="Potential null dereference with no structural citation",
        affected_path=[],
    )

    audit, verified = verify(
        candidate=candidate,
        bundle=bundle,
        mode=ReasonerMode.A,
        finding=finding,
        config=IntelligenceConfig(),
        full_repo_scan=True,
    )

    assert audit.verifier_outcome == VerifierOutcome.partially_confirmed
    assert verified.uncited is True
    assert audit.failed_rule == "LLM output contains no bundle node/edge citation"


def test_global_alias_analysis_trigger_auto_grayzones() -> None:
    candidate = _candidate(detector_name="sql-injection-approx", taint_chain_present=True)
    bundle = _bundle(
        taint_edges=[
            TaintEdge(
                source_node="source",
                sink_node="sink",
                intermediate_path=["source", "scope", "sink"],
                sink_pattern="sql query builder",
                scope="scope",
            )
        ]
    )
    finding = _mode_a(
        bug_type="sql-injection",
        description="Potential SQL injection at [node:scope] but requires full alias analysis",
        affected_path=["scope"],
    )

    audit, verified = verify(
        candidate=candidate,
        bundle=bundle,
        mode=ReasonerMode.A,
        finding=finding,
        config=IntelligenceConfig(),
        full_repo_scan=True,
    )

    assert audit.verifier_outcome == VerifierOutcome.partially_confirmed
    assert verified.verifier_outcome == VerifierOutcome.partially_confirmed
    assert audit.failed_rule == "requires full alias analysis"
