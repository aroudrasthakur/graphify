"""Product-facing depOS output assembly.

This module intentionally runs after the canonical pipeline has produced a
``RunResult``. It must not feed back into candidate selection, verification,
ranking, or gray-zone evaluation.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from depos.analysis.config import IntelligenceConfig
from depos.analysis.schemas import (
    CIDecision,
    Confidence,
    ContextBundle,
    Finding,
    FindingStatus,
    GraphReliability,
    ProductAffectedSurface,
    ProductCIPolicy,
    ProductEvidence,
    ProductFinding,
    ProductImpactPath,
    ProductImpactPathEdge,
    ProductImpactPathNode,
    ProductMCPContext,
    ProductRunSummary,
    RecommendedAction,
    RiskCategory,
    RunMode,
    RunResult,
    VerifierAuditEntry,
    VerifierOutcome,
)

SCHEMA_VERSION = "1.0"
MAX_MCP_EVIDENCE = 5
MAX_EVIDENCE_CHARS = 600

_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s,;}]+"),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._\-]+"),
]


def product_outputs_enabled() -> bool:
    raw = os.getenv("DEPOS_PRODUCT_OUTPUTS_ENABLED", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def mode_from_analysis(mode_value: str) -> RunMode:
    if mode_value == "dataset":
        return RunMode.dataset
    if mode_value == "diff_aware":
        return RunMode.pr
    if mode_value == "full_repo_scan":
        return RunMode.full_repo
    return RunMode.unknown


def resolve_product_output_dir(
    mode: RunMode,
    result: RunResult,
    config: IntelligenceConfig,
    existing_out_dir: Path | None = None,
) -> Path:
    if existing_out_dir is not None:
        return existing_out_dir
    return Path(config.data_dir) / config.run_output_subdir / result.run_metadata.run_id


def write_product_outputs(
    out_dir: Path,
    result: RunResult,
    mode: RunMode,
    config: IntelligenceConfig,
) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    run_id = result.run_metadata.run_id
    findings = build_product_findings(result)
    impact_paths = [finding.impact_path for finding in findings if finding.impact_path is not None]
    ci_decision = build_ci_decision(findings)
    summary = ProductRunSummary(
        run_id=run_id,
        mode=mode,
        findings_total=len(findings),
        verified_total=sum(1 for finding in findings if finding.status == FindingStatus.verified),
        review_total=sum(1 for finding in findings if finding.review_only),
        graph_reliability=_run_graph_reliability(result),
    )
    docs: dict[str, dict[str, Any]] = {
        "findings": _artifact_base(run_id, mode, generated_at)
        | {"findings": [finding.model_dump(mode="json") for finding in findings]},
        "impact_paths": _artifact_base(run_id, mode, generated_at)
        | {"impact_paths": [path.model_dump(mode="json") for path in impact_paths]},
        "triage_backlog": _artifact_base(run_id, mode, generated_at)
        | _triage_backlog(result, findings),
        "mcp_context": _artifact_base(run_id, mode, generated_at)
        | {"contexts": [context.model_dump(mode="json") for context in build_mcp_contexts(findings)]},
        "product_summary": _artifact_base(run_id, mode, generated_at)
        | {
            "summary": summary.model_dump(mode="json"),
            "ci_decision": ci_decision.model_dump(mode="json"),
        },
    }
    paths: dict[str, str] = {}
    filenames = {
        "findings": "findings.json",
        "impact_paths": "impact_paths.json",
        "triage_backlog": "triage_backlog.json",
        "mcp_context": "mcp_context.json",
        "product_summary": "product_summary.json",
    }
    for logical_name, payload in docs.items():
        path = out_dir / filenames[logical_name]
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        paths[logical_name] = str(path)
    result.run_metadata.output_paths.update(paths)
    summary.output_paths = paths
    return paths


def build_product_findings(result: RunResult) -> list[ProductFinding]:
    audit_by_id = {audit.finding_id: audit for audit in result.verifier_audits}
    bundle_by_candidate = {bundle.candidate_id: bundle for bundle in result.bundles}
    gray_ids = {row.finding_id for row in result.gray_zone_rows}
    graph_reliability = _run_graph_reliability(result)
    product_findings: list[ProductFinding] = []
    for finding in result.findings:
        candidate_id = finding.finding_id.split(":", 1)[0]
        bundle = bundle_by_candidate.get(candidate_id)
        audit = audit_by_id.get(finding.finding_id)
        product_findings.append(
            _product_finding(
                finding,
                bundle=bundle,
                audit=audit,
                is_gray=finding.finding_id in gray_ids,
                graph_reliability=graph_reliability,
            )
        )
    return product_findings


def build_ci_decision(findings: list[ProductFinding], policy: ProductCIPolicy | None = None) -> CIDecision:
    policy = policy or ProductCIPolicy()
    critical_verified = [
        finding.finding_id
        for finding in findings
        if finding.status == FindingStatus.verified and finding.severity == "critical"
    ]
    high_verified = [
        finding.finding_id
        for finding in findings
        if finding.status == FindingStatus.verified and finding.severity == "high"
    ]
    blocking: list[str] = []
    if policy.block_on_critical_verified and len(critical_verified) > policy.max_allowed_critical:
        blocking.extend(critical_verified)
    if policy.block_on_high_verified:
        max_high = policy.max_allowed_high
        if max_high is None or len(high_verified) > max_high:
            blocking.extend(high_verified)
    return CIDecision(
        should_block=bool(blocking),
        blocking_finding_ids=sorted(set(blocking)),
        policy_snapshot=policy,
        reason="blocking_product_findings" if blocking else "policy_passed",
    )


def build_mcp_contexts(findings: list[ProductFinding]) -> list[ProductMCPContext]:
    contexts: list[ProductMCPContext] = []
    for finding in findings:
        uncertainties = list(finding.caveats)
        if finding.graph_reliability in {GraphReliability.low, GraphReliability.partial}:
            uncertainties.append(f"graph_reliability={finding.graph_reliability.value}")
        if finding.impact_confidence in {Confidence.low, Confidence.unknown}:
            uncertainties.append(f"impact_confidence={finding.impact_confidence.value}")
        review_only = finding.review_only or finding.recommended_action == RecommendedAction.request_review
        contexts.append(
            ProductMCPContext(
                finding_id=finding.finding_id,
                review_only=review_only,
                summary=finding.description,
                evidence=finding.evidence[:MAX_MCP_EVIDENCE],
                uncertainties=sorted(set(uncertainties)),
                suggested_fix_strategy="" if review_only else "Use the cited evidence and affected surfaces to make a minimal targeted fix.",
            )
        )
    return contexts


def _product_finding(
    finding: Finding,
    *,
    bundle: ContextBundle | None,
    audit: VerifierAuditEntry | None,
    is_gray: bool,
    graph_reliability: GraphReliability,
) -> ProductFinding:
    status = _product_status(finding, is_gray)
    finding_confidence = _finding_confidence(finding, audit)
    coverage_sensitive = _is_coverage_sensitive(finding, bundle)
    impact_confidence = _impact_confidence(graph_reliability, coverage_sensitive)
    recommended_action = _recommended_action(status, finding.severity, graph_reliability, impact_confidence)
    caveats = _product_caveats(finding, graph_reliability, coverage_sensitive)
    evidence = _product_evidence(finding, bundle)
    impact_path = _impact_path(finding, bundle, graph_reliability)
    return ProductFinding(
        finding_id=finding.finding_id,
        legacy_finding_id=finding.finding_id,
        title=finding.bug_type or finding.detector_name or "Architecture risk",
        description=finding.description,
        risk_category=_risk_category(finding),
        status=status,
        severity=finding.severity,
        finding_confidence=finding_confidence,
        impact_confidence=impact_confidence,
        graph_reliability=graph_reliability,
        recommended_action=recommended_action,
        affected_surfaces=[
            ProductAffectedSurface(component=component, confidence=impact_confidence)
            for component in finding.affected_components
        ],
        evidence=evidence,
        impact_path=impact_path,
        caveats=caveats,
        review_only=recommended_action == RecommendedAction.request_review,
        advisory_validity=audit.advisory_validity if audit is not None else "unknown",
    )


def _artifact_base(run_id: str, mode: RunMode, generated_at: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "mode": mode.value,
        "generated_at": generated_at,
    }


def _run_graph_reliability(result: RunResult) -> GraphReliability:
    coverage = result.run_metadata.stitcher_coverage
    if result.run_metadata.low_stitcher_coverage or coverage.low_coverage:
        return GraphReliability.low
    if coverage.total_fastapi_routes or coverage.total_celery_tasks:
        return GraphReliability.high if coverage.coverage_ratio >= 0.8 else GraphReliability.partial
    return GraphReliability.unknown


def _product_status(finding: Finding, is_gray: bool) -> FindingStatus:
    if finding.verifier_outcome == VerifierOutcome.confirmed:
        return FindingStatus.verified
    if finding.verifier_outcome == VerifierOutcome.invalid_reasoning:
        return FindingStatus.invalid
    if is_gray or finding.verifier_outcome.canonical == "GRAY-ZONE":
        return FindingStatus.gray_zone
    return FindingStatus.review_only


def _finding_confidence(finding: Finding, audit: VerifierAuditEntry | None) -> Confidence:
    if audit is not None and audit.advisory_validity == "needs_review":
        return Confidence.medium
    if finding.verifier_outcome == VerifierOutcome.confirmed:
        return Confidence.high
    if finding.reasoner_confidence >= 0.7:
        return Confidence.medium
    if finding.reasoner_confidence > 0:
        return Confidence.low
    return Confidence.unknown


def _impact_confidence(reliability: GraphReliability, coverage_sensitive: bool) -> Confidence:
    if not coverage_sensitive:
        return Confidence.high
    if reliability == GraphReliability.high:
        return Confidence.high
    if reliability == GraphReliability.partial:
        return Confidence.low
    if reliability == GraphReliability.low:
        return Confidence.low
    return Confidence.unknown


def _recommended_action(
    status: FindingStatus,
    severity: str,
    reliability: GraphReliability,
    impact_confidence: Confidence,
) -> RecommendedAction:
    if status == FindingStatus.invalid:
        return RecommendedAction.dismiss
    if status != FindingStatus.verified:
        return RecommendedAction.request_review
    if reliability in {GraphReliability.low, GraphReliability.partial} and impact_confidence != Confidence.high:
        return RecommendedAction.request_review
    if severity in {"critical", "high"}:
        return RecommendedAction.fix
    return RecommendedAction.monitor


def _risk_category(finding: Finding) -> RiskCategory:
    text = f"{finding.bug_type} {finding.detector_name}".lower()
    if any(token in text for token in ("secret", "token", "auth", "rls", "sql", "taint")):
        return RiskCategory.security
    if any(token in text for token in ("dep", "version", "manifest")):
        return RiskCategory.dependency
    if any(token in text for token in ("env", "config")):
        return RiskCategory.config
    if any(token in text for token in ("schema", "api", "contract")):
        return RiskCategory.schema
    if any(token in text for token in ("null", "bounds", "runtime")):
        return RiskCategory.runtime
    return RiskCategory.architecture if finding.affected_components else RiskCategory.unknown


def _is_coverage_sensitive(finding: Finding, bundle: ContextBundle | None) -> bool:
    text = f"{finding.bug_type} {finding.detector_name}".lower()
    if any(token in text for token in ("route", "api", "contract", "schema", "cross", "seam", "rls")):
        return True
    return bool(bundle and (bundle.seam_edges or bundle.cross_language_seams or bundle.edge_facts))


def _product_caveats(
    finding: Finding,
    reliability: GraphReliability,
    coverage_sensitive: bool,
) -> list[str]:
    caveats = [
        text
        for text in [
            finding.partially_confirmed_caveat,
            finding.evaluator_surfaced_caveat,
            finding.low_stitcher_coverage_caveat,
            finding.stale_diff_replay_caveat,
        ]
        if text
    ]
    if coverage_sensitive and reliability in {GraphReliability.low, GraphReliability.partial}:
        caveats.append("Graph coverage is incomplete for this coverage-sensitive impact claim.")
    return caveats


def _product_evidence(finding: Finding, bundle: ContextBundle | None) -> list[ProductEvidence]:
    evidence: list[ProductEvidence] = []
    if finding.evidence_text:
        evidence.append(
            ProductEvidence(
                kind="finding_text",
                text=_redact_and_cap(finding.evidence_text),
                redacted=_contains_secret(finding.evidence_text),
            )
        )
    if bundle is not None:
        for snippet in bundle.code_snippets[:MAX_MCP_EVIDENCE]:
            text = snippet.text or ""
            evidence.append(
                ProductEvidence(
                    kind="snippet",
                    node_id=snippet.node_id,
                    source_file=snippet.source_file or "",
                    start_line=snippet.start_line,
                    end_line=snippet.end_line,
                    text=_redact_and_cap(text),
                    redacted=_contains_secret(text),
                    quality=snippet.evidence_quality,
                )
            )
    return evidence[:MAX_MCP_EVIDENCE]


def _impact_path(
    finding: Finding,
    bundle: ContextBundle | None,
    reliability: GraphReliability,
) -> ProductImpactPath:
    node_ids = list(dict.fromkeys(finding.witness_path))
    edges: list[ProductImpactPathEdge] = []
    if bundle is not None:
        for edge in bundle.edge_facts:
            if edge.source in node_ids or edge.target in node_ids:
                edges.append(
                    ProductImpactPathEdge(
                        source=edge.source,
                        target=edge.target,
                        relation=edge.relation,
                        inferred=edge.inferred,
                        confidence=edge.confidence,
                    )
                )
                if edge.source not in node_ids:
                    node_ids.append(edge.source)
                if edge.target not in node_ids:
                    node_ids.append(edge.target)
    return ProductImpactPath(
        finding_id=finding.finding_id,
        nodes=[ProductImpactPathNode(node_id=node_id) for node_id in node_ids],
        edges=edges,
        graph_reliability=reliability,
    )


def _triage_backlog(result: RunResult, findings: list[ProductFinding]) -> dict[str, Any]:
    reasoner_candidate_ids = {trace.candidate_id for trace in result.bundle_trace if trace.reasoner_attempts > 0}
    low_evidence_candidate_ids = [
        trace.candidate_id
        for trace in result.bundle_trace
        if trace.skipped_reason in {
            "low_evidence",
            "detector_policy_disabled",
            "detector_policy_min_evidence",
            "detector_policy_max_candidates",
        }
    ]
    finding_candidate_ids = {finding.finding_id.split(":", 1)[0] for finding in result.findings}
    return {
        "unreasoned_candidates": [
            candidate.candidate_id
            for candidate in result.candidates
            if candidate.candidate_id not in reasoner_candidate_ids
        ],
        "gray_zone_findings": [
            finding.model_dump(mode="json")
            for finding in findings
            if finding.status in {FindingStatus.gray_zone, FindingStatus.review_only}
        ],
        "suppressed_candidates": [
            candidate.candidate_id
            for candidate in result.candidates
            if candidate.candidate_id not in finding_candidate_ids
        ],
        "low_evidence_candidates": low_evidence_candidate_ids,
    }


def _redact_and_cap(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: match.group(0).split("=", 1)[0] + "=[REDACTED]" if "=" in match.group(0) else "[REDACTED]", redacted)
    if len(redacted) > MAX_EVIDENCE_CHARS:
        return redacted[:MAX_EVIDENCE_CHARS] + "..."
    return redacted


def _contains_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in _SECRET_PATTERNS)
