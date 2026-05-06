"""All Pydantic models for the depOS intelligence layer.

Single source of truth. Import from here everywhere. Do not create a
``depos/intelligence_types.py`` module.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

NodeId = str
EdgeId = str

# Detector trust calibration: approximate/heuristic detectors must not surface as
# formally *confirmed* solely from heuristic + probe passage (see verifier cap).
ConfirmationTier = Literal["formal", "approximate", "heuristic"]


# ---------------------------------------------------------------------------
# Module 1 — semantic edges & coverage
# ---------------------------------------------------------------------------

class ContractKind(str, Enum):
    http = "http"
    rpc = "rpc"
    queue = "queue"
    schema = "schema"
    rls = "rls"


class RLSCoverage(str, Enum):
    full = "full"
    partial_operation = "partial_operation"
    partial_predicate = "partial_predicate"
    context_mismatch = "context_mismatch"
    none = "none"


class MigrationState(str, Enum):
    exists_in_branch = "exists_in_branch"
    exists_only_in_later_migration = "exists_only_in_later_migration"
    removed_in_branch = "removed_in_branch"
    ambiguous = "ambiguous"


class SemanticEdgeMetadata(BaseModel):
    """Attached to every enriched edge emitted by Module 1."""

    model_config = ConfigDict(extra="allow")

    confidence: float = 1.0
    inferred: bool = False
    source_system: Optional[str] = None
    target_system: Optional[str] = None
    contract_kind: Optional[ContractKind] = None

    api_method: Optional[str] = None
    route_pattern: Optional[str] = None
    table_name: Optional[str] = None
    column_name: Optional[str] = None
    rpc_name: Optional[str] = None
    task_name: Optional[str] = None
    payload_fields: list[str] = Field(default_factory=list)
    migration_id: Optional[str] = None
    migration_order: Optional[int] = None
    branch_visible: Optional[bool] = None
    rls_policy_id: Optional[str] = None
    rls_command: Optional[str] = None
    rls_coverage: Optional[RLSCoverage] = None


class StitcherCoverageReport(BaseModel):
    total_fastapi_routes: int = 0
    linked_routes: int = 0
    unlinked_routes: list[str] = Field(default_factory=list)
    coverage_ratio: float = 0.0
    low_coverage: bool = False
    errors: list[dict[str, Any]] = Field(default_factory=list)

    total_celery_tasks: int = 0
    matched_producer_consumer_pairs: int = 0

    rls_nodes_found: int = 0
    migration_files_found: int = 0


class NodeKind(str, Enum):
    package_manifest = "package_manifest"
    package_dep = "package_dep"
    lockfile_resolution = "lockfile_resolution"
    env_var = "env_var"
    config_key = "config_key"
    prompt_template = "prompt_template"
    openapi_operation = "openapi_operation"
    openapi_schema = "openapi_schema"
    next_route = "next_route"
    next_middleware = "next_middleware"
    infra_workflow = "infra_workflow"
    infra_service = "infra_service"
    dockerfile_stage = "dockerfile_stage"


class Universe(str, Enum):
    code = "code"
    deps = "deps"
    env = "env"
    prompt = "prompt"
    schema = "schema"
    nextjs = "nextjs"
    infra = "infra"


# ---------------------------------------------------------------------------
# Module 2 — candidates
# ---------------------------------------------------------------------------

class SeedType(str, Enum):
    diff_anchor = "diff_anchor"
    interface_surface = "interface_surface"
    graph_anomaly = "graph_anomaly"
    ai_driven = "ai_driven"


class AnalysisMode(str, Enum):
    diff_aware = "diff_aware"
    full_repo_scan = "full_repo_scan"


SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
PersistedFindingTrustLevel = Literal["confirmed", "partially_confirmed", "evaluator_surfaced"]
RunStatus = Literal["running", "succeeded", "partial_reasoning", "failed"]
ReasonerRunHealth = Literal["ok", "degraded", "failed"]


class DiffHunkSpan(BaseModel):
    """Inclusive 1-based line range on the **post-change** file for a git diff hunk."""

    start_line: int = Field(ge=1, description="First touched line in the new file.")
    end_line: int = Field(ge=1, description="Last touched line in the new file.")


class ChangeManifestEntry(BaseModel):
    path: Optional[str] = None
    node_ids: list[NodeId] = Field(default_factory=list)
    high_churn_file: bool = False
    dropped_from_budget: list[NodeId] = Field(default_factory=list)
    migration_change: bool = False
    file_change: bool = False
    hunks: list[DiffHunkSpan] = Field(
        default_factory=list,
        description="Line ranges derived from unified diffs; used to narrow graph nodes when line attrs exist.",
    )


class ChangeManifest(BaseModel):
    entries: list[ChangeManifestEntry] = Field(default_factory=list)
    resolved_via: str = "git"  # "cpg_diff" | "git" | "manual"


class DetectorAction(BaseModel):
    emit: Literal["candidate", "skip", "stop"]
    seed_type: SeedType = SeedType.graph_anomaly
    extra: dict[str, Any] = Field(default_factory=dict)
    witness_template: list[str] = Field(default_factory=list)


class DetectorRule(BaseModel):
    if_: str
    then: DetectorAction
    description: str = ""


class Detector(BaseModel):
    name: str
    version: str
    universe: Universe
    applies_when: str
    tree: list[DetectorRule] = Field(default_factory=list)
    verifier_checks: list[str] = Field(default_factory=list)
    requires_reasoner: bool = False
    severity_default: SeverityLevel = "medium"
    enabled_by_default: bool = True
    scope: Literal["graph", "per_node", "per_edge"] = "per_node"
    # None = Group A (no layer). "cfg" = B. "dfg" / "taint" = C.
    semantic_requirement: Optional[Literal["cfg", "dfg", "taint"]] = None
    # formal: verifier may mark confirmed. approximate/heuristic: confirmed is capped
    # to partially_confirmed with an explicit caveat (names with "-approx", etc.).
    confirmation_tier: ConfirmationTier = "formal"





class CandidateScore(BaseModel):
    """Vector score; ``composite`` is the deterministic global sort key."""

    structural_centrality: float = 0.0
    seam_exposure: float = 0.0
    change_proximity: float = 0.0
    detector_confidence: float = 0.0
    evidence_quality: float = 0.0
    # Set by taint pre-computation, not by detectors. Required by verifier
    # gate for security findings — lives on the score vector (not in
    # DetectorPayload) so ranking can use it.
    taint_chain_present: bool = False
    # Fan-in cone normalised via min(1.0, fan_in / 50). Computed from
    # GraphMetrics, not by detectors. Makes blast radius a first-class
    # ranking dimension.
    blast_radius_norm: float = 0.0
    composite: float = 0.0


class DetectorPayload(BaseModel):
    """Typed detector output; use ``raw`` for seed-specific or transitional keys."""

    model_config = ConfigDict(extra="allow")

    category: str = "unknown"
    detector_name: str = ""
    detector_version: str = ""
    pipeline_version: str = ""
    severity: SeverityLevel = "medium"
    oracle_hints: dict[str, Any] = Field(default_factory=dict)
    requires_cfg: bool = False
    requires_dfg: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


# Referenced on candidates and in context bundles; defined before :class:`Candidate`.
class SeamEdge(BaseModel):
    """Cross-language or cross-unit seam on the graph (candidate + bundle)."""

    edge_id: EdgeId
    source: NodeId
    target: NodeId
    relation: str
    source_language: str = ""
    target_language: str = ""
    pattern: str = "unknown"
    contract_defined: bool = False
    contract_verified: bool = False
    metadata: SemanticEdgeMetadata = Field(default_factory=SemanticEdgeMetadata)

    @computed_field
    @property
    def risk(self) -> float:
        base = {
            "ffi": 0.9,
            "unknown": 0.85,
            "generic": 0.85,
            "wasm": 0.75,
            "ipc": 0.7,
            "rpc": 0.7,
            "serverless": 0.7,
            "queue": 0.6,
            "schema": 0.55,
            "http": 0.5,
            "http_bridge": 0.5,
        }.get(self.pattern, 0.85)
        return base if not self.contract_verified else base * 0.4


class TaintEdge(BaseModel):
    """Typed taint source -> sink on the graph; single source of truth for every consumer.

    ``intermediate_path`` is the full ordered chain from source to sink. Until
    inter-procedural taint is implemented it degrades to ``[source_node,
    sink_node]``; the validator guarantees the endpoints are always present.
    """

    source_node: NodeId
    sink_node: NodeId
    intermediate_path: list[NodeId]
    crosses_seam: bool = False
    seam_edges_crossed: list[SeamEdge] = Field(default_factory=list)
    source_chain: str = ""
    sink_pattern: str = ""
    source_hints: list[str] = Field(default_factory=list)
    scope: str = ""
    line: int = 0

    @model_validator(mode="after")
    def _path_must_include_endpoints(self) -> "TaintEdge":
        if not self.intermediate_path:
            raise ValueError(
                "intermediate_path must contain at least [source_node, sink_node]"
            )
        if self.intermediate_path[0] != self.source_node:
            raise ValueError("intermediate_path must start with source_node")
        if self.intermediate_path[-1] != self.sink_node:
            raise ValueError("intermediate_path must end with sink_node")
        return self


class Candidate(BaseModel):
    candidate_id: str
    scope_id: str
    seed_type: SeedType
    language_path: list[str] = Field(default_factory=list)
    language_pair: Optional[str] = None  # deprecated; use language_path[0:2]
    seam_edges: list[SeamEdge] = Field(default_factory=list)
    diff_anchors: list[NodeId] = Field(default_factory=list)
    analysis_mode: AnalysisMode = AnalysisMode.diff_aware
    score: CandidateScore = Field(default_factory=CandidateScore)
    detector_payload: DetectorPayload = Field(default_factory=DetectorPayload)
    ranking_metadata: Optional[RankingMetadata] = None


class DetectorRunStats(BaseModel):
    run_id: str
    detector_name: str
    detector_version: str
    candidates_emitted: int = 0
    verified_confirmed: int = 0
    verified_invalid: int = 0
    mean_latency_ms: float = 0.0
    errors: list[dict[str, Any]] = Field(default_factory=list)
    # When the detector did not run because CFG/DFG/taint was unavailable for all scopes.
    skip_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Module 3 — context bundles
# ---------------------------------------------------------------------------

class CodeSnippet(BaseModel):
    node_id: NodeId
    source_file: Optional[str] = None
    start_line: int = 0
    end_line: int = 0
    text: str = ""
    evidence_quality: Literal["full", "embedded", "label_only", "missing"] = "full"
    resolved_via: Optional[str] = None


class PackManifest(BaseModel):
    manifest_id: str
    token_estimator: str = "chars4"  # "chars4" | "tiktoken-cl100k" | ...
    included: list[str] = Field(default_factory=list)
    truncated: list[str] = Field(default_factory=list)
    dropped: list[str] = Field(default_factory=list)
    truncation_order_applied: list[str] = Field(default_factory=list)


class BundleNodeFact(BaseModel):
    node_id: NodeId
    node_kind: str = ""
    universe: str = "code"
    defined: bool = False
    incoming_relations: list[str] = Field(default_factory=list)
    outgoing_relations: list[str] = Field(default_factory=list)


class BundleEdgeFact(BaseModel):
    edge_id: EdgeId = ""
    source: NodeId
    target: NodeId
    relation: str = ""
    inferred: bool = False
    confidence: float = 1.0
    source_universe: str = "code"
    target_universe: str = "code"
    payload_missing_fields: list[str] = Field(default_factory=list)
    payload_extra_fields: list[str] = Field(default_factory=list)


class BundleEvidence(BaseModel):
    """Per-bundle evidence-quality summary used to gate the reasoner.

    ``evidence_score`` is a deterministic 0..1 number computed in
    :func:`depos.analysis.context_bundle._compute_evidence` so the same bundle
    always scores the same way across runs.
    """

    snippet_count: int = 0
    snippets_full: int = 0
    snippets_embedded: int = 0
    snippets_label_only: int = 0
    snippets_missing: int = 0
    has_seams: bool = False
    has_data_reads: bool = False
    has_data_writes: bool = False
    has_rls_coverage: bool = False
    has_migration_state: bool = False
    evidence_score: float = 0.0
    missing_pieces: list[str] = Field(default_factory=list)


class ContextBundle(BaseModel):
    bundle_id: str
    candidate_id: str
    scope_id: str
    # Resolved function/method node for this candidate (for semantic-layer flags).
    scope_node_id: str = ""
    scope_text: str = ""
    scope_language: str = ""
    # Deterministic sort key + full score vector (prompt + queue metadata).
    score_composite: float = 0.0
    candidate_score: CandidateScore = Field(default_factory=CandidateScore)
    cfg_available: bool = False
    dfg_available: bool = False
    taint_edges_available: bool = False

    callers: list[NodeId] = Field(default_factory=list)
    callees: list[NodeId] = Field(default_factory=list)
    caller_texts: dict[NodeId, str] = Field(default_factory=dict)
    callee_texts: dict[NodeId, str] = Field(default_factory=dict)
    call_chain_in: list[dict[str, Any]] = Field(default_factory=list)
    call_chain_out: list[dict[str, Any]] = Field(default_factory=list)
    node_facts: dict[NodeId, BundleNodeFact] = Field(default_factory=dict)
    edge_facts: list[BundleEdgeFact] = Field(default_factory=list)
    data_reads: list[str] = Field(default_factory=list)
    data_writes: list[str] = Field(default_factory=list)
    seam_edges: list[SeamEdge] = Field(default_factory=list)
    cross_language_seams: list[SeamEdge] = Field(default_factory=list)
    seam_neighbor_texts: dict[NodeId, str] = Field(default_factory=dict)
    is_articulation_point: bool = False
    pagerank_percentile: float = 0.0
    scc_size: int = 1
    on_cross_lang_cycle: bool = False
    taint_edges: list[TaintEdge] = Field(default_factory=list)
    graph_distance_to_diff: int = -1
    cfg_summary: Optional[str] = None
    null_paths: Optional[list[list[str]]] = None
    diff_anchors: list[dict[str, Any]] = Field(default_factory=list)
    rls_coverage: dict[str, RLSCoverage] = Field(default_factory=dict)
    migration_state: dict[str, MigrationState] = Field(default_factory=dict)
    code_snippets: list[CodeSnippet] = Field(default_factory=list)

    pack_manifest: PackManifest
    token_budget: int = 0
    truncation_events: list[str] = Field(default_factory=list)
    evidence: BundleEvidence = Field(default_factory=BundleEvidence)


GraphContextBundle = ContextBundle


# ---------------------------------------------------------------------------
# Module 4 — reasoner outputs
# ---------------------------------------------------------------------------

class ReasonerMode(str, Enum):
    A = "A"
    B = "B"
    C = "C"


class ModeAFinding(BaseModel):
    bug_type: str
    description: str
    trigger_condition: str = ""
    affected_path: list[NodeId] = Field(default_factory=list)
    confidence: float = 0.0
    graph_anchor_nodes: list[NodeId] = Field(default_factory=list)


class ModeAOutput(BaseModel):
    mode: ReasonerMode = ReasonerMode.A
    findings: list[ModeAFinding] = Field(default_factory=list)


class ModeBFinding(BaseModel):
    violation_type: str
    description: str
    component_a: str
    component_b: str
    disagreement: str
    confidence: float = 0.0
    graph_anchor_nodes: list[NodeId] = Field(default_factory=list)


class ModeBOutput(BaseModel):
    mode: ReasonerMode = ReasonerMode.B
    findings: list[ModeBFinding] = Field(default_factory=list)


class ModeCFinding(BaseModel):
    flow_bug_type: str
    description: str
    operation: str
    violating_path: list[NodeId] = Field(default_factory=list)
    missing_guard: str = ""
    confidence: float = 0.0
    graph_anchor_nodes: list[NodeId] = Field(default_factory=list)


class ModeCOutput(BaseModel):
    mode: ReasonerMode = ReasonerMode.C
    findings: list[ModeCFinding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Module 5 — ranker
# ---------------------------------------------------------------------------

class RankingMetadata(BaseModel):
    """Stores attack pattern labels separately from detector identity."""
    
    matched_pattern: Optional[str] = None


class RankerDiffFeatures(BaseModel):
    changed_nodes_on_path: int = 0
    removed_entities_referenced: int = 0
    cross_lang_seams_on_path: int = 0
    unresolved_symbols: int = 0
    missing_guard_signals: int = 0
    candidate_score_composite: float = 0.0


class RankerInput(BaseModel):
    candidate_id: str
    invariant_id: Optional[str] = None
    candidate_path: list[NodeId] = Field(default_factory=list)
    edge_sequence: list[str] = Field(default_factory=list)
    node_attrs: dict[str, Any] = Field(default_factory=dict)
    diff_features: RankerDiffFeatures = Field(default_factory=RankerDiffFeatures)


class RankerScore(BaseModel):
    candidate_id: str
    score: float
    ranking_phase: int = 0
    components: dict[str, float] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Module 6 — verifier
# ---------------------------------------------------------------------------

class VerifierOutcome(str, Enum):
    confirmed = "confirmed"
    partially_confirmed = "partially_confirmed"
    unconfirmed = "unconfirmed"
    invalid_reasoning = "invalid_reasoning"
    evaluator_surfaced = "evaluator_surfaced"

    @property
    def canonical(self) -> str:
        return {
            "confirmed": "CONFIRMED",
            "partially_confirmed": "GRAY-ZONE",
            "unconfirmed": "GRAY-ZONE",
            "invalid_reasoning": "GRAY-ZONE",
            "evaluator_surfaced": "GRAY-ZONE",
        }.get(self.value, "GRAY-ZONE")


class VerifierCheckResult(BaseModel):
    name: str
    result: str  # "pass" | "fail" | "unavailable" | "rls_covered" | "rls_partial" | "insufficient_static_evidence" | "invalid" | "skip" | "outcome_n_a"
    detail: str = ""


class VerifierStageResult(BaseModel):
    stage: str
    result: Literal["pass", "fail", "unavailable", "skip"] = "unavailable"
    detail: str = ""


class VerifierAuditEntry(BaseModel):
    finding_id: str
    verifier_outcome: VerifierOutcome
    checks_run: list[VerifierCheckResult] = Field(default_factory=list)
    inferred_edge_confidence_floor_applied: bool = False
    pack_manifest_id: str = ""
    reasoner_mode: Optional[ReasonerMode] = None
    surfaced: bool = False
    failed_rule: str = ""
    missing_evidence: list[str] = Field(default_factory=list)
    stage_results: list[VerifierStageResult] = Field(default_factory=list)
    advisory_validity: Literal["valid", "needs_review", "invalid", "unknown"] = "unknown"
    advisory_reason: str = ""


# ---------------------------------------------------------------------------
# Module 7 — gray zone
# ---------------------------------------------------------------------------

class GrayZoneEntryReason(str, Enum):
    partially_confirmed_1_check = "partially_confirmed_1_check"
    unconfirmed_high_confidence = "unconfirmed_high_confidence"
    all_inferred_edges = "all_inferred_edges"
    rls_context_mismatch = "rls_context_mismatch"
    low_stitcher_coverage = "low_stitcher_coverage"


class GrayZoneVote(str, Enum):
    bug = "bug"
    no_bug = "no_bug"
    uncertain = "uncertain"
    confirmed = "confirmed"
    refuted = "refuted"


class GrayZoneVoteOutcome(str, Enum):
    evaluator_surfaced = "evaluator_surfaced"
    hold_for_review = "hold_for_review"
    discard = "discard"


class GrayZoneAuditRow(BaseModel):
    finding_id: str
    entry_reason: GrayZoneEntryReason
    model_a_verdict: GrayZoneVote
    model_a_confidence: float = 0.0
    model_a_reasoning: str = ""
    model_b_verdict: GrayZoneVote
    model_b_counter_reasoning: str = ""
    model_c_structural_questions: list[str] = Field(default_factory=list)
    model_c_graph_answers: list[str] = Field(default_factory=list)
    model_c_verdict: GrayZoneVote
    vote_outcome: GrayZoneVoteOutcome
    surfaced: bool = False
    final_label: str = ""
    training_export: bool = True
    # Structured gray-zone (Phase 5)
    failed_rule: str = ""
    missing_evidence: list[str] = Field(default_factory=list)
    confidence_range: tuple[float, float] = (0.0, 1.0)
    recommended_action: Literal["REVIEW_REQUIRED", "MONITOR", "DISMISS"] = "REVIEW_REQUIRED"


class BundleTraceEntry(BaseModel):
    bundle_id: str
    candidate_id: str
    detector_name: str = ""
    candidate_score_composite: float = 0.0
    reasoner_modes_returned: list[str] = Field(default_factory=list)
    findings: int = 0
    skipped_reason: str = ""
    reasoner_skipped: bool = False
    reasoner_skip_reason: str = ""
    reasoner_skip_detail: dict[str, Any] = Field(default_factory=dict)
    evidence_quality: str = ""
    evidence_score: float = 0.0
    reasoner_attempts: int = 0
    reasoner_successes: int = 0
    reasoner_failures: int = 0


# ---------------------------------------------------------------------------
# Output: violations.json
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    finding_id: str
    trust_level: VerifierOutcome
    mode: Optional[ReasonerMode] = None
    verifier_outcome: VerifierOutcome
    bug_type: str = ""
    description: str = ""
    affected_components: list[str] = Field(default_factory=list)
    witness_path: list[NodeId] = Field(default_factory=list)
    missing_guard: Optional[str] = None
    recommended_fix: Optional[str] = None
    reasoner_confidence: float = 0.0
    ranking_phase: int = 0
    verifier_checks_passed: list[str] = Field(default_factory=list)
    verifier_checks_inconclusive: list[str] = Field(default_factory=list)
    rls_verdict: Optional[RLSCoverage] = None
    migration_state_facts: dict[str, str] = Field(default_factory=dict)
    pack_manifest_id: str = ""
    detector_name: str = "legacy"
    detector_version: str = "0"
    pipeline_version: str = "0"
    severity: SeverityLevel = "medium"

    partially_confirmed_caveat: Optional[str] = None
    evaluator_surfaced_caveat: Optional[str] = None
    low_stitcher_coverage_caveat: Optional[str] = None
    stale_diff_replay_caveat: Optional[str] = None

    # LLM output lacks any bundle node/edge id in the narrative (Block 11).
    uncited: bool = False
    evidence_text: str = ""


# ---------------------------------------------------------------------------
# Product-facing outputs
# ---------------------------------------------------------------------------

class RiskCategory(str, Enum):
    dependency = "dependency"
    config = "config"
    schema = "schema"
    security = "security"
    runtime = "runtime"
    architecture = "architecture"
    unknown = "unknown"


class Confidence(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class GraphReliability(str, Enum):
    high = "high"
    partial = "partial"
    low = "low"
    unknown = "unknown"


class RecommendedAction(str, Enum):
    fix = "fix"
    monitor = "monitor"
    request_review = "request_review"
    dismiss = "dismiss"


class FindingStatus(str, Enum):
    verified = "verified"
    gray_zone = "gray_zone"
    review_only = "review_only"
    invalid = "invalid"


class RunMode(str, Enum):
    pr = "pr"
    full_repo = "full_repo"
    dataset = "dataset"
    ci = "ci"
    unknown = "unknown"


class ProductEvidence(BaseModel):
    kind: str = "snippet"
    node_id: str = ""
    source_file: str = ""
    start_line: int = 0
    end_line: int = 0
    text: str = ""
    redacted: bool = False
    quality: str = ""


class ProductImpactPathNode(BaseModel):
    node_id: str
    label: str = ""
    kind: str = ""


class ProductImpactPathEdge(BaseModel):
    source: str
    target: str
    relation: str = ""
    inferred: bool = False
    confidence: float = 1.0


class ProductImpactPath(BaseModel):
    finding_id: str
    nodes: list[ProductImpactPathNode] = Field(default_factory=list)
    edges: list[ProductImpactPathEdge] = Field(default_factory=list)
    graph_reliability: GraphReliability = GraphReliability.unknown


class ProductAffectedSurface(BaseModel):
    component: str
    surface_type: str = "unknown"
    confidence: Confidence = Confidence.unknown


class ProductMCPContext(BaseModel):
    finding_id: str
    review_only: bool = False
    summary: str = ""
    evidence: list[ProductEvidence] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    suggested_fix_strategy: str = ""


class ProductFinding(BaseModel):
    finding_id: str
    legacy_finding_id: str
    title: str = ""
    description: str = ""
    risk_category: RiskCategory = RiskCategory.unknown
    status: FindingStatus = FindingStatus.review_only
    severity: SeverityLevel = "medium"
    finding_confidence: Confidence = Confidence.unknown
    impact_confidence: Confidence = Confidence.unknown
    graph_reliability: GraphReliability = GraphReliability.unknown
    recommended_action: RecommendedAction = RecommendedAction.request_review
    affected_surfaces: list[ProductAffectedSurface] = Field(default_factory=list)
    evidence: list[ProductEvidence] = Field(default_factory=list)
    impact_path: ProductImpactPath | None = None
    caveats: list[str] = Field(default_factory=list)
    review_only: bool = False
    advisory_validity: Literal["valid", "needs_review", "invalid", "unknown"] = "unknown"


class ProductRunSummary(BaseModel):
    run_id: str
    mode: RunMode = RunMode.unknown
    findings_total: int = 0
    verified_total: int = 0
    review_total: int = 0
    graph_reliability: GraphReliability = GraphReliability.unknown
    output_paths: dict[str, str] = Field(default_factory=dict)


class ProductCIPolicy(BaseModel):
    block_on_critical_verified: bool = True
    block_on_high_verified: bool = False
    block_on_gray_zone: bool = False
    max_allowed_critical: int = 0
    max_allowed_high: int | None = None


class CIDecision(BaseModel):
    should_block: bool = False
    blocking_finding_ids: list[str] = Field(default_factory=list)
    policy_snapshot: ProductCIPolicy = Field(default_factory=ProductCIPolicy)
    reason: str = ""


class PreselectionInfo(BaseModel):
    total_candidates: int = 0
    eligible_candidates: int = 0
    bundled_candidates: int = 0
    selected_candidates: int = 0
    min_score: float | None = None
    bundle_limit: int | None = None
    selected_limit: int | None = None
    sort_key: str = "(-CandidateScore.composite, candidate_id)"


# ---------------------------------------------------------------------------
# Training data rows
# ---------------------------------------------------------------------------

class RankerExample(BaseModel):
    example_id: str
    candidate_path: list[NodeId]
    edge_sequence: list[str]
    node_attrs: dict[str, Any] = Field(default_factory=dict)
    diff_features: RankerDiffFeatures
    label: str  # "suspicious" | "not_suspicious"
    label_source: str  # "verifier_confirmed" | "verifier_contradicted" | "evaluator_all_reject" | "reviewer_dismissed"
    confidence: float = 0.0
    ranking_phase_at_creation: int = 0
    repo_id: str = ""
    base_ref: str = ""
    head_ref: str = ""


class ReasonerExample(BaseModel):
    example_id: str
    mode: ReasonerMode
    evidence_pack: dict[str, Any] = Field(default_factory=dict)
    pack_manifest: PackManifest
    expected_output_json: dict[str, Any] = Field(default_factory=dict)
    verifier_outcome: VerifierOutcome
    evaluator_outcome: Optional[GrayZoneVoteOutcome] = None
    label_source: str = ""
    repo_id: str = ""
    base_ref: str = ""
    head_ref: str = ""


ReasonerFailureReason = Literal[
    "transport",
    "empty_response",
    "not_json",
    "json_but_invalid_schema",
    "empty_findings",
    "low_evidence",
    "other",
]


class ReasonerQueueRow(BaseModel):
    bundle_id: str
    candidate_id: str
    mode: ReasonerMode
    evidence_pack: dict[str, Any] = Field(default_factory=dict)
    pack_manifest: PackManifest
    score_composite: float = 0.0
    ranking_phase: int = 0
    queued_at: datetime
    failure_reason: ReasonerFailureReason = "other"
    http_status: Optional[int] = None
    attempt_count: int = 0
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
    raw_response_excerpt: str = ""
    provider_name: str = ""
    model: str = ""
    request_payload_sha256: str = ""
    prompt_token_estimate: int = 0
    response_path_used: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ReasonerCallStats(BaseModel):
    """Aggregate counters that explain ``reasoner_run_health``.

    ``by_reason`` keys come from :data:`ReasonerFailureReason`.
    ``by_mode`` is shaped as ``{mode: {"successes": N, "failures": M}}``.
    """

    attempts: int = 0
    successes: int = 0
    failures: int = 0
    by_reason: dict[str, int] = Field(default_factory=dict)
    by_mode: dict[str, dict[str, int]] = Field(default_factory=dict)

    def record_success(self, mode: str) -> None:
        self.attempts += 1
        self.successes += 1
        bucket = self.by_mode.setdefault(mode, {"successes": 0, "failures": 0})
        bucket["successes"] += 1

    def record_failure(self, mode: str, reason: str) -> None:
        self.attempts += 1
        self.failures += 1
        self.by_reason[reason] = self.by_reason.get(reason, 0) + 1
        bucket = self.by_mode.setdefault(mode, {"successes": 0, "failures": 0})
        bucket["failures"] += 1

    def merge(self, other: "ReasonerCallStats") -> None:
        self.attempts += other.attempts
        self.successes += other.successes
        self.failures += other.failures
        for reason, count in other.by_reason.items():
            self.by_reason[reason] = self.by_reason.get(reason, 0) + count
        for mode, bucket in other.by_mode.items():
            target = self.by_mode.setdefault(mode, {"successes": 0, "failures": 0})
            target["successes"] += bucket.get("successes", 0)
            target["failures"] += bucket.get("failures", 0)

    def health(self) -> ReasonerRunHealth:
        if self.attempts == 0:
            return "ok"
        if self.successes == 0:
            return "failed"
        if self.successes / self.attempts < 0.5:
            return "degraded"
        return "ok"


class IngestReport(BaseModel):
    module: str
    nodes_added: int = 0
    edges_added: int = 0
    files_seen: int = 0
    errors: list[dict[str, Any]] = Field(default_factory=list)


class OracleResult(BaseModel):
    found: bool = False
    conclusion: Literal["pass", "fail", "insufficient_evidence"] = "insufficient_evidence"
    detail: str = ""
    source: str = ""


# ---------------------------------------------------------------------------
# Run metadata
# ---------------------------------------------------------------------------

class RunMetadata(BaseModel):
    run_id: str
    repo_id: str = ""
    base_ref: str = ""
    head_ref: str = ""
    analysis_mode: AnalysisMode = AnalysisMode.diff_aware
    provider: str = ""
    token_estimator: str = "chars4"
    ranking_phase: int = 0
    low_stitcher_coverage: bool = False
    partial_reasoning: bool = False
    pipeline_version: str = "1"
    detector_versions: dict[str, str] = Field(default_factory=dict)
    enabled_detectors: list[str] = Field(default_factory=list)
    disabled_detectors: list[str] = Field(default_factory=list)
    universes_present: list[Universe] = Field(default_factory=list)
    ingest_errors: list[dict[str, Any]] = Field(default_factory=list)
    stitcher_coverage: StitcherCoverageReport = Field(default_factory=StitcherCoverageReport)
    graph_source_metadata: dict[str, Any] = Field(default_factory=dict)
    reasoner_call_stats: ReasonerCallStats = Field(default_factory=ReasonerCallStats)
    reasoner_run_health: ReasonerRunHealth = "ok"
    reasoner_health_reason: str = ""
    bundles_built: int = 0
    bundles_sent_to_reasoner: int = 0
    bundles_skipped_low_evidence: int = 0
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    reasoner_policy_summary: dict[str, Any] = Field(default_factory=dict)
    dataset_path_resolution: dict[str, Any] = Field(default_factory=dict)
    preselection_info: PreselectionInfo | None = None
    output_paths: dict[str, str] = Field(default_factory=dict)


class RunResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    detector_stats: list[DetectorRunStats] = Field(default_factory=list)
    ingest_reports: list[IngestReport] = Field(default_factory=list)
    run_metadata: RunMetadata
    reasoner_call_stats: ReasonerCallStats = Field(default_factory=ReasonerCallStats)
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    change_manifest: ChangeManifest | None = None
    candidates: list[Candidate] = Field(default_factory=list)
    bundles: list[ContextBundle] = Field(default_factory=list)
    verifier_audits: list[VerifierAuditEntry] = Field(default_factory=list)
    gray_zone_rows: list[GrayZoneAuditRow] = Field(default_factory=list)
    bundle_trace: list[BundleTraceEntry] = Field(default_factory=list)
