"""Typed objects for deterministic pattern-backed detector candidates."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


PatternScopeType = Literal[
    "file",
    "function",
    "class",
    "route",
    "frontend_call",
    "migration",
    "rls_policy",
    "celery_task",
    "prompt",
    "config",
    "env_var",
    "node",
]


class PatternEvidence(BaseModel):
    """A replayable witness produced by a primitive pattern probe."""

    model_config = ConfigDict(extra="allow")

    kind: str
    message: str = ""
    node_id: Optional[str] = None
    edge_id: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    data: dict[str, Any] = Field(default_factory=dict)


class PatternScope(BaseModel):
    """A graph/source unit that a pattern rule can evaluate."""

    model_config = ConfigDict(extra="allow")

    scope_id: str
    scope_type: PatternScopeType = "node"
    file_path: Optional[str] = None
    node_id: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    language: Optional[str] = None


class PatternMatch(BaseModel):
    """A deterministic match that can be converted into a depOS Candidate."""

    model_config = ConfigDict(extra="allow")

    rule_id: str
    detector_name: str
    scope: PatternScope
    matched_text: Optional[str] = None
    metavars: dict[str, str] = Field(default_factory=dict)
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    evidence: list[PatternEvidence] = Field(default_factory=list)
    confidence: float = 1.0


class PatternRule(BaseModel):
    """Reviewable built-in rule spec for the v1 pattern layer."""

    model_config = ConfigDict(extra="allow")

    id: str
    detector_name: str
    risk_category: str
    severity: str = "medium"
    scope: str = "node"
    semantic_requirement: Optional[Literal["cfg", "dfg", "taint"]] = None
    message: str
    formula: dict[str, Any]


__all__ = [
    "PatternEvidence",
    "PatternMatch",
    "PatternRule",
    "PatternScope",
    "PatternScopeType",
]
