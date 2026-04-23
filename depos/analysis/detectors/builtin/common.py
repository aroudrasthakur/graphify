"""Shared helpers for builtin detectors."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Literal, Optional

import networkx as nx

from depos.analysis.schemas import (
    AnalysisMode,
    Candidate,
    CandidateScore,
    Detector,
    DetectorAction,
    DetectorPayload,
    DetectorRule,
    SeamEdge,
    SeedType,
    SemanticEdgeMetadata,
    Universe,
)
from depos.analysis.scoring import apply_composite

_UNSET = object()


def simple_spec(
    *,
    name: str,
    universe: Universe,
    verifier_checks: list[str],
    requires_reasoner: bool = False,
    severity: str = "medium",
    applies_when: str = "True",
    semantic_requirement: Optional[Literal["cfg", "dfg", "taint"]] | object = _UNSET,
) -> Detector:
    if semantic_requirement is _UNSET:
        raise ValueError(
            f"Detector {name!r} must explicitly set semantic_requirement. "
            "Use semantic_requirement=None for Group A (graph-only) detectors."
        )
    return Detector(
        name=name,
        version="0.1.0",
        universe=universe,
        applies_when=applies_when,
        tree=[
            DetectorRule(
                if_="True",
                then=DetectorAction(emit="candidate"),
                description=f"Builtin detector {name}",
            )
        ],
        verifier_checks=verifier_checks,
        requires_reasoner=requires_reasoner,
        severity_default=severity,  # type: ignore[arg-type]
        semantic_requirement=semantic_requirement,
    )


def seam_edges_from_ids(edge_ids: Iterable[str]) -> list[SeamEdge]:
    return [
        SeamEdge(
            edge_id=eid,
            source="",
            target="",
            relation="detector_ref",
            metadata=SemanticEdgeMetadata(),
        )
        for eid in edge_ids
    ]


# Normalisation constant for seam_exposure: exposure saturates at 3 seam edges.
_SEAM_EXPOSURE_SATURATION = 3.0


def _derive_vector_dimensions(
    *,
    diff_anchors: list[str],
    seam_edge_ids: list[str],
) -> tuple[float, float]:
    """Compute ``change_proximity`` and ``seam_exposure`` from candidate shape."""
    change_proximity = 1.0 if diff_anchors else 0.0
    seam_exposure = min(1.0, len(seam_edge_ids) / _SEAM_EXPOSURE_SATURATION)
    return change_proximity, seam_exposure


def make_candidate(
    *,
    scope_id: str,
    seed_type: SeedType,
    detector_confidence: float,
    analysis_mode: AnalysisMode,
    diff_anchors: Iterable[str] | None = None,
    seam_edges: Iterable[str] | None = None,
    language_pair: str | None = None,
    extra: dict[str, Any] | None = None,
    config: Any = None,
    requires_cfg: bool = False,
    requires_dfg: bool = False,
) -> Candidate:
    import hashlib

    da_list = list(diff_anchors or [])
    se_list = list(seam_edges or [])
    payload = f"{scope_id}|{seed_type.value}|{sorted(da_list)}|{sorted(se_list)}"
    cid = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]
    change_proximity, seam_exposure = _derive_vector_dimensions(
        diff_anchors=da_list, seam_edge_ids=se_list
    )
    score = CandidateScore(
        detector_confidence=float(detector_confidence),
        change_proximity=change_proximity,
        seam_exposure=seam_exposure,
        structural_centrality=0.0,
        taint_chain_present=False,
        blast_radius_norm=0.0,
    )
    apply_composite(score, mode=analysis_mode, config=config)
    det = DetectorPayload(
        category=seed_type.value,
        raw=dict(extra or {}),
        requires_cfg=requires_cfg,
        requires_dfg=requires_dfg,
    )
    return Candidate(
        candidate_id=f"cand_{seed_type.value}_{cid}",
        scope_id=scope_id,
        seed_type=seed_type,
        language_pair=language_pair,
        seam_edges=seam_edges_from_ids(se_list),
        diff_anchors=da_list,
        analysis_mode=analysis_mode,
        score=score,
        detector_payload=det,
    )


def build_seed_candidate(
    *,
    candidate_id: str,
    scope_id: str,
    seed_type: SeedType,
    detector_confidence: float,
    analysis_mode: AnalysisMode,
    diff_anchors: list[str] | None = None,
    seam_edge_ids: list[str] | None = None,
    language_pair: str | None = None,
    raw: dict[str, Any] | None = None,
    config: Any = None,
) -> Candidate:
    """Used by :mod:`candidate_identifier` for manifest-driven seeds (explicit id)."""
    da_list = list(diff_anchors or [])
    se_list = list(seam_edge_ids or [])
    change_proximity, seam_exposure = _derive_vector_dimensions(
        diff_anchors=da_list, seam_edge_ids=se_list
    )
    score = CandidateScore(
        detector_confidence=float(detector_confidence),
        change_proximity=change_proximity,
        seam_exposure=seam_exposure,
        structural_centrality=0.0,
        taint_chain_present=False,
        blast_radius_norm=0.0,
    )
    apply_composite(score, mode=analysis_mode, config=config)
    return Candidate(
        candidate_id=candidate_id,
        scope_id=scope_id,
        seed_type=seed_type,
        language_pair=language_pair,
        seam_edges=seam_edges_from_ids(se_list),
        diff_anchors=da_list,
        analysis_mode=analysis_mode,
        score=score,
        detector_payload=DetectorPayload(category=seed_type.value, raw=dict(raw or {})),
    )


def iter_nodes_by_kind(graph: nx.DiGraph, kind: str) -> list[tuple[str, dict[str, Any]]]:
    return [
        (node_id, attrs)
        for node_id, attrs in graph.nodes(data=True)
        if str(attrs.get("node_kind") or attrs.get("kind") or "") == kind
    ]


def incoming_by_relation(graph: nx.DiGraph, node_id: str, relation: str | None = None) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for source, _, data in graph.in_edges(node_id, data=True):
        if relation is None or data.get("relation") == relation:
            out.append((source, dict(data)))
    return out


def outgoing_by_relation(graph: nx.DiGraph, node_id: str, relation: str | None = None) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for _, target, data in graph.out_edges(node_id, data=True):
        if relation is None or data.get("relation") == relation:
            out.append((target, dict(data)))
    return out


def package_groups(graph: nx.DiGraph) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    groups: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for node_id, attrs in iter_nodes_by_kind(graph, "package_dep"):
        pkg = str(attrs.get("package_name") or attrs.get("name") or "").strip()
        if pkg:
            groups[pkg].append((node_id, attrs))
    return groups


__all__ = [
    "build_seed_candidate",
    "incoming_by_relation",
    "iter_nodes_by_kind",
    "make_candidate",
    "outgoing_by_relation",
    "package_groups",
    "seam_edges_from_ids",
    "simple_spec",
]
