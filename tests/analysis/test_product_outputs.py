from __future__ import annotations

import json
from pathlib import Path

from depos.analysis.config import IntelligenceConfig
from depos.analysis.product_outputs import (
    build_ci_decision,
    build_mcp_contexts,
    build_product_findings,
    write_product_outputs,
)
from depos.analysis.schemas import (
    AnalysisMode,
    BundleEvidence,
    CodeSnippet,
    Confidence,
    ContextBundle,
    Finding,
    GraphReliability,
    PackManifest,
    ProductCIPolicy,
    RecommendedAction,
    RunMetadata,
    RunMode,
    RunResult,
    StitcherCoverageReport,
    VerifierAuditEntry,
    VerifierOutcome,
)


def _finding(
    *,
    finding_id: str = "cand-1:finding",
    severity: str = "critical",
    outcome: VerifierOutcome = VerifierOutcome.confirmed,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        trust_level=outcome,
        verifier_outcome=outcome,
        bug_type="api_contract_change",
        description="Route contract changed with incomplete route coverage.",
        witness_path=["node:a", "node:b"],
        severity=severity,
        detector_name="api-contract-detector",
        reasoner_confidence=0.9,
        evidence_text="token=super-secret-value",
    )


def _bundle() -> ContextBundle:
    return ContextBundle(
        bundle_id="bundle-1",
        candidate_id="cand-1",
        scope_id="node:a",
        pack_manifest=PackManifest(manifest_id="m1"),
        evidence=BundleEvidence(snippet_count=1, snippets_full=1, evidence_score=1.0),
        code_snippets=[
            CodeSnippet(
                node_id="node:a",
                source_file="app.py",
                start_line=1,
                end_line=2,
                text="API_TOKEN=abc123",
            )
        ],
    )


def _result() -> RunResult:
    return RunResult(
        findings=[_finding()],
        run_metadata=RunMetadata(
            run_id="run-product",
            analysis_mode=AnalysisMode.full_repo_scan,
            low_stitcher_coverage=True,
            stitcher_coverage=StitcherCoverageReport(
                total_fastapi_routes=4,
                linked_routes=1,
                coverage_ratio=0.25,
                low_coverage=True,
            ),
        ),
        bundles=[_bundle()],
        verifier_audits=[
            VerifierAuditEntry(
                finding_id="cand-1:finding",
                verifier_outcome=VerifierOutcome.confirmed,
                advisory_validity="needs_review",
            )
        ],
    )


def test_product_findings_keep_graph_reliability_product_only() -> None:
    findings = build_product_findings(_result())

    assert findings[0].graph_reliability == GraphReliability.low
    assert findings[0].impact_confidence == Confidence.low
    assert findings[0].recommended_action == RecommendedAction.request_review
    assert findings[0].review_only is True


def test_write_product_outputs_uses_stable_artifact_shapes(tmp_path: Path) -> None:
    paths = write_product_outputs(
        tmp_path,
        _result(),
        RunMode.full_repo,
        IntelligenceConfig(data_dir=tmp_path / "data"),
    )

    assert set(paths) == {
        "findings",
        "impact_paths",
        "triage_backlog",
        "mcp_context",
        "product_summary",
    }
    payload = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.0"
    assert payload["run_id"] == "run-product"
    assert payload["mode"] == "full_repo"
    assert "generated_at" in payload
    assert payload["findings"][0]["legacy_finding_id"] == "cand-1:finding"


def test_mcp_context_redacts_and_marks_uncertain_findings_review_only() -> None:
    context = build_mcp_contexts(build_product_findings(_result()))[0]

    assert context.review_only is True
    assert context.suggested_fix_strategy == ""
    assert context.uncertainties
    assert "[REDACTED]" in context.evidence[0].text


def test_product_ci_decision_blocks_critical_only_by_default() -> None:
    critical = build_product_findings(_result())[0]
    high = critical.model_copy(update={"finding_id": "high", "severity": "high"})

    decision = build_ci_decision([critical, high])

    assert decision.should_block is True
    assert decision.blocking_finding_ids == ["cand-1:finding"]


def test_product_ci_policy_can_block_high_verified() -> None:
    high = build_product_findings(_result())[0].model_copy(
        update={
            "finding_id": "high",
            "severity": "high",
            "recommended_action": RecommendedAction.fix,
            "review_only": False,
        }
    )

    decision = build_ci_decision([high], ProductCIPolicy(block_on_high_verified=True, max_allowed_high=0))

    assert decision.should_block is True
    assert decision.blocking_finding_ids == ["high"]
