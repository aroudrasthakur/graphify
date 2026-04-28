"""Pydantic models for Graphical Intent Context (GIC) reports."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

GIC_REPORT_SCHEMA_VERSION = 2

GicUnitStatus = Literal["supported", "partial", "unresolved", "conflict"]

GicUnresolvedReason = Literal[
    "none",
    "no_matching_file",
    "no_graph_nodes_for_file",
    "empty_scope_hints",
    "path_outside_repo",
    "insufficient_graph_signal",
    "sha_mismatch_degraded",
]

GicEvidenceKind = Literal[
    "scope_hint_path",
    "evidence_chunk_path",
    "coverage_tag_line",
    "trace_hint",
    "oft_covers",
]


class GicEvidenceRef(BaseModel):
    kind: GicEvidenceKind
    detail: str = ""
    node_id: Optional[str] = None
    source_file: Optional[str] = None
    line: Optional[int] = None


class GicUnitResult(BaseModel):
    unit_id: str
    natural_language: str = ""
    effective_tier: str = "P2"
    effective_weight: float = Field(ge=0.0, le=1.0, default=0.0)
    extractor: str = ""
    status: GicUnitStatus
    unresolved_reason: GicUnresolvedReason = "none"
    structural_confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    evidence: list[GicEvidenceRef] = Field(default_factory=list)


class GicIntentLayerMetrics(BaseModel):
    intent_units_total: int = 0
    intent_units_by_extractor: dict[str, int] = Field(default_factory=dict)
    intent_tier_mix: dict[str, int] = Field(default_factory=dict)
    intent_trace_hints_file_present: bool = False
    intent_unresolved_rate: float = 0.0
    trace_hint_coverage_p0: float = 0.0


class GicGraphLayerMetrics(BaseModel):
    gic_resolved_rate_p0: float = 0.0
    gic_resolved_rate_p1: float = 0.0
    gic_partial_rate_p0: float = 0.0
    gic_unresolved_rate_p0: float = 0.0
    gic_path_alignment: float = 0.0
    unresolved_reason_counts: dict[str, int] = Field(default_factory=dict)
    gic_seam_reach: Optional[float] = None
    graph_orphan_feature_count: int = 0


class GicCompositeMetrics(BaseModel):
    gic_alignment_score: float = Field(ge=0.0, le=1.0, default=0.0)
    strict_p0_unresolved_max: int = 0
    p0_unresolved_weighted: float = 0.0


class GicOrphanHint(BaseModel):
    node_id: str
    source_file: str = ""
    in_degree: int = 0
    label: str = ""


class GicReport(BaseModel):
    gic_schema_version: int = GIC_REPORT_SCHEMA_VERSION
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    repo_root: str = ""
    intent_dir: str = ""
    graph_source: str = ""
    commit_alignment: Literal["match", "mismatch", "unknown"] = "unknown"
    intent_repo_sha: str = "unknown"
    current_head_sha: str = "unknown"
    warnings: list[str] = Field(default_factory=list)
    intent_layer: GicIntentLayerMetrics = Field(default_factory=GicIntentLayerMetrics)
    graph_layer: GicGraphLayerMetrics = Field(default_factory=GicGraphLayerMetrics)
    composite: GicCompositeMetrics = Field(default_factory=GicCompositeMetrics)
    units: list[GicUnitResult] = Field(default_factory=list)
    top_gaps: list[GicUnitResult] = Field(default_factory=list)
    orphan_hints: list[GicOrphanHint] = Field(default_factory=list)
    llm_assist_disambiguation_count: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)
