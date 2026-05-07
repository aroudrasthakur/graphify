"""Typed verifier rules for reasoner-backed findings."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class VerifierRule(BaseModel):
    finding_category: str
    required_score_dimensions: dict[str, Any]
    required_bundle_evidence: list[str]
    auto_grayzone_conditions: list[str]


ARCHITECTURE_BLAST_RADIUS_THRESHOLD = 0.12


VERIFIER_RULES: dict[str, VerifierRule] = {
    "security": VerifierRule(
        finding_category="security",
        required_score_dimensions={"taint_chain_present": True},
        required_bundle_evidence=[
            "taint_edges",
            "taint_sources_in_bundle",
            "taint_sinks_in_bundle",
        ],
        auto_grayzone_conditions=[
            "taint_chain crosses unmodeled sanitizer",
            "taint source is reflection or dynamic dispatch",
            "requires heap object identity",
            "requires full alias analysis",
        ],
    ),
    "architecture": VerifierRule(
        finding_category="architecture",
        required_score_dimensions={},
        required_bundle_evidence=["is_articulation_point_or_blast_radius_above_threshold"],
        auto_grayzone_conditions=[
            "requires inter-procedural CFG beyond call graph composition",
        ],
    ),
    "correctness": VerifierRule(
        finding_category="correctness",
        required_score_dimensions={"cfg_available": True},
        required_bundle_evidence=["cfg_summary"],
        auto_grayzone_conditions=[
            "cfg_available is False",
            "requires dynamic dispatch resolution",
        ],
    ),
}


GLOBAL_AUTO_GRAYZONE: list[str] = [
    "LLM output contains no bundle node/edge citation",
    "requires full alias analysis",
    "requires dynamic dispatch resolution",
    "requires inter-procedural CFG beyond call graph composition",
    "requires heap object identity",
    "passes through unmodeled sanitizer",
]


DETECTOR_CATEGORY_MAP: dict[str, str] = {
    "articulation-point-high-fanin": "architecture",
    "auth-bypass-approx": "security",
    "awaitable-returned-unawaited": "correctness",
    "command-injection-approx": "security",
    "compose-service-depends-on-service-with-different-network": "architecture",
    "cookie-set-without-httponly-or-secure-in-prod": "security",
    "cors-origin-omits-known-client-origin": "security",
    "cross-lang-cycle": "architecture",
    "dead-code": "architecture",
    "dep-version-mismatch-across-workspaces": "correctness",
    "dockerfile-copies-path-not-in-build-context": "correctness",
    "enum-value-used-but-not-in-schema": "correctness",
    "env-var-defined-but-unused": "correctness",
    "env-var-exposed": "security",
    "env-var-referenced-but-undefined": "correctness",
    "env-var-typed-drift": "correctness",
    "error-swallowed-in-async-handler": "correctness",
    "gha-matrix-node-version-diverges-from-engines": "correctness",
    "gha-workflow-uses-secret-not-declared": "correctness",
    "graph-anomaly": "architecture",
    "high-centrality-isolated": "architecture",
    "infinite-loop": "correctness",
    "integer-overflow-approx": "correctness",
    "lockfile-drift": "correctness",
    "logic-inversion-approx": "correctness",
    "migration-adds-not-null-without-default": "correctness",
    "next-route-protected-in-middleware-but-not-layout": "security",
    "null-dereference-approx": "correctness",
    "off-by-one-approx": "correctness",
    "orphan-surface": "architecture",
    "password-reset-link-handler-redirects-to-external-origin": "security",
    "peer-dep-unsatisfied": "correctness",
    "phantom-dep": "correctness",
    "privilege-escalation-approx": "security",
    "prompt-drift-between-provider-versions": "correctness",
    "prompt-field-type-mismatch": "correctness",
    "prompt-missing-required-field": "correctness",
    "prompt-references-undefined-variable": "correctness",
    "race-condition-approx": "correctness",
    "redirect-target-not-safelisted": "security",
    "request-body-missing-required-field": "correctness",
    "response-field-consumed-but-not-produced": "correctness",
    "route-without-session-check": "security",
    "rpc-invoked-without-rls-or-service-role": "security",
    "seam-contract-drift": "architecture",
    "sql-injection-approx": "security",
    "transaction-started-but-not-committed-on-all-branches": "correctness",
    "transitive-pin-conflict": "correctness",
    "unhandled-exception-path": "correctness",
    "uninit-variable-approx": "correctness",
    "unreachable-branch": "correctness",
    "unused-dep": "correctness",
    "use-after-free-approx": "correctness",
    "vulnerable-dep": "security",
}


BUG_TYPE_CATEGORY_MAP: dict[str, str] = {
    "articulation-point-high-fanin": "architecture",
    "auth-bypass": "security",
    "auth-bypass-approx": "security",
    "command-injection": "security",
    "command-injection-approx": "security",
    "cross-lang-cycle": "architecture",
    "dead-code": "architecture",
    "integer-overflow": "correctness",
    "integer-overflow-approx": "correctness",
    "logic-inversion": "correctness",
    "logic-inversion-approx": "correctness",
    "null-dereference": "correctness",
    "null-dereference-approx": "correctness",
    "off-by-one": "correctness",
    "off-by-one-approx": "correctness",
    "orphan-surface": "architecture",
    "privilege-escalation": "security",
    "privilege-escalation-approx": "security",
    "race-condition-approx": "correctness",
    "seam-contract-drift": "architecture",
    "sql-injection": "security",
    "sql-injection-approx": "security",
    "unhandled-exception-path": "correctness",
    "uninit-variable": "correctness",
    "uninit-variable-approx": "correctness",
    "unreachable-branch": "correctness",
    "use-after-free": "correctness",
    "use-after-free-approx": "correctness",
}


def _normalize(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def resolve_finding_category(*, detector_name: str, bug_type: str) -> str | None:
    normalized_bug_type = _normalize(bug_type) if bug_type else ""
    normalized_detector = _normalize(detector_name) if detector_name else ""
    if normalized_bug_type:
        category = BUG_TYPE_CATEGORY_MAP.get(normalized_bug_type)
        if category is not None:
            return category
    if normalized_detector:
        category = DETECTOR_CATEGORY_MAP.get(normalized_detector)
        if category is not None:
            return category
    return None


__all__ = [
    "ARCHITECTURE_BLAST_RADIUS_THRESHOLD",
    "GLOBAL_AUTO_GRAYZONE",
    "VERIFIER_RULES",
    "VerifierRule",
    "resolve_finding_category",
]
