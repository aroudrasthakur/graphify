"""Shared helpers for builtin detectors."""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Iterable, Literal, Optional

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

if TYPE_CHECKING:
    from depos.analysis.run_context import RunContext

_UNSET = object()

def read_source_text_safely(repo_root: Any, rel: str) -> str | None:
    if not repo_root or not rel:
        return None
    try:
        from pathlib import Path
        p = (repo_root / rel).resolve()
        if not p.is_file():
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None


def infer_confirmation_tier(name: str) -> Literal["formal", "approximate", "heuristic"]:
    """Map detector id to trust tier (approximate detectors cannot be formally *confirmed*)."""
    lowered = name.lower()
    if "-approx" in lowered:
        return "approximate"
    return "formal"


def simple_spec(
    *,
    name: str,
    universe: Universe,
    verifier_checks: list[str],
    requires_reasoner: bool = False,
    severity: str = "medium",
    applies_when: str = "True",
    semantic_requirement: Optional[Literal["cfg", "dfg", "taint"]] | object = _UNSET,
    confirmation_tier: Literal["formal", "approximate", "heuristic"] | None = None,
) -> Detector:
    if semantic_requirement is _UNSET:
        raise ValueError(
            f"Detector {name!r} must explicitly set semantic_requirement. "
            "Use semantic_requirement=None for Group A (graph-only) detectors."
        )
    tier = confirmation_tier if confirmation_tier is not None else infer_confirmation_tier(name)
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
        confirmation_tier=tier,
    )


def _endpoints_from_canonical_edge_id(edge_id: str) -> tuple[str, str] | None:
    raw = str(edge_id)
    if "->" not in raw:
        return None
    source, target = raw.split("->", 1)
    if not source or not target:
        return None
    return source, target


def _seam_from_record(record: Any, *, edge_id: str) -> SeamEdge | None:
    source = str(getattr(record, "source", getattr(record, "u", "")) or "")
    target = str(getattr(record, "target", getattr(record, "v", "")) or "")
    if not source or not target:
        return None
    relation = str(getattr(record, "relation", "") or "detector_ref")
    source_language = str(getattr(record, "source_language", "") or "")
    target_language = str(getattr(record, "target_language", "") or "")
    pattern = str(getattr(record, "pattern", "unknown") or "unknown")
    contract_defined = bool(getattr(record, "contract_defined", False))
    contract_verified = bool(getattr(record, "contract_verified", False))
    metadata = getattr(record, "metadata", None)
    if metadata is not None:
        resolved_metadata = (
            metadata
            if isinstance(metadata, SemanticEdgeMetadata)
            else SemanticEdgeMetadata.model_validate(metadata)
        )
    else:
        resolved_metadata = SemanticEdgeMetadata(
            source_system=str(getattr(record, "source_language", "") or ""),
            target_system=str(getattr(record, "target_language", "") or ""),
        )
    return SeamEdge(
        edge_id=str(getattr(record, "edge_id", edge_id) or edge_id),
        source=source,
        target=target,
        relation=relation,
        source_language=source_language,
        target_language=target_language,
        pattern=pattern,
        contract_defined=contract_defined,
        contract_verified=contract_verified,
        metadata=resolved_metadata,
    )


def _resolve_seam_edges(
    seam_edge_ids: Iterable[str],
    run_context: "RunContext | None",
    graph: nx.DiGraph | None,
) -> list[SeamEdge]:
    resolved: list[SeamEdge] = []
    seam_index = getattr(run_context, "seam_edge_index", {}) or {}
    for edge_id in seam_edge_ids:
        record = seam_index.get(edge_id)
        seam = _seam_from_record(record, edge_id=str(edge_id)) if record is not None else None
        if seam is not None:
            resolved.append(seam)
            continue
        endpoints = _endpoints_from_canonical_edge_id(str(edge_id))
        if endpoints is None or graph is None or not graph.has_edge(*endpoints):
            continue
        data = dict(graph.get_edge_data(*endpoints) or {})
        source_attrs = graph.nodes[endpoints[0]] if graph.has_node(endpoints[0]) else {}
        target_attrs = graph.nodes[endpoints[1]] if graph.has_node(endpoints[1]) else {}
        metadata = SemanticEdgeMetadata.model_validate({k: v for k, v in data.items() if k != "relation"})
        if not metadata.source_system:
            metadata.source_system = str(
                data.get("source_system")
                or source_attrs.get("language")
                or source_attrs.get("lang")
                or ""
            )
        if not metadata.target_system:
            metadata.target_system = str(
                data.get("target_system")
                or target_attrs.get("language")
                or target_attrs.get("lang")
                or ""
            )
        relation = str(data.get("relation") or data.get("label") or "detector_ref")
        seam_info = dict(data.get("seam") or {})
        resolved.append(
            SeamEdge(
                edge_id=str(edge_id),
                source=endpoints[0],
                target=endpoints[1],
                relation=relation,
                source_language=str(
                    seam_info.get("source_language")
                    or source_attrs.get("language")
                    or source_attrs.get("lang")
                    or ""
                ),
                target_language=str(
                    seam_info.get("target_language")
                    or target_attrs.get("language")
                    or target_attrs.get("lang")
                    or ""
                ),
                pattern=str(seam_info.get("pattern") or "unknown"),
                contract_defined=bool(seam_info.get("contract_defined", False)),
                contract_verified=bool(seam_info.get("contract_verified", False)),
                metadata=metadata,
            )
        )
    return resolved


def _language_path_from_seams(seam_edges: list[SeamEdge]) -> list[str]:
    ordered: list[str] = []
    for seam in seam_edges:
        for language in (seam.source_language, seam.target_language):
            value = str(language or "").strip()
            if value and value not in ordered:
                ordered.append(value)
    return ordered


def _seam_exposure_value(seam_edges: list[SeamEdge]) -> float:
    return max((float(seam.risk) for seam in seam_edges), default=0.0)


def _score_node_id(scope_id: str, diff_anchors: list[str]) -> str:
    if scope_id.startswith("node:") and len(scope_id) > 5:
        return scope_id[5:]
    if scope_id:
        return scope_id
    return diff_anchors[0] if diff_anchors else ""


def _bfs_distance(graph: nx.DiGraph, scope_id: str, diff_anchors: list[str]) -> int | None:
    if not scope_id or not diff_anchors or not graph.has_node(scope_id):
        return None
    targets = [node_id for node_id in diff_anchors if graph.has_node(node_id)]
    if not targets:
        return None
    if scope_id in targets:
        return 0
    try:
        lengths = nx.single_source_shortest_path_length(graph.to_undirected(as_view=True), scope_id)
    except Exception:  # noqa: BLE001
        return None
    distances = [int(lengths[target]) for target in targets if target in lengths]
    return min(distances) if distances else None


def _compute_change_proximity(
    diff_anchors: list[str],
    scope_id: str,
    graph: nx.DiGraph | None,
    run_context: "RunContext | None",
) -> float:
    score_node = _score_node_id(scope_id, diff_anchors)
    if diff_anchors:
        if graph is None:
            return 1.0
        distance = _bfs_distance(graph, score_node, diff_anchors)
        if distance is None:
            return 0.0
        return 1.0 / (1.0 + float(distance))
    manifest = getattr(run_context, "manifest", None)
    if manifest is not None and getattr(manifest, "resolved_via", "") in ("git", "empty"):
        metrics = getattr(run_context, "graph_metrics", None)
        pagerank = getattr(metrics, "pagerank", {}) if metrics is not None else {}
        return float(pagerank.get(score_node, 0.0))
    return 0.0


def _derive_vector_dimensions(
    *,
    scope_id: str,
    diff_anchors: list[str],
    seam_edges: list[SeamEdge],
    graph: nx.DiGraph | None,
    run_context: "RunContext | None",
) -> tuple[float, float]:
    """Compute ``change_proximity`` and ``seam_exposure`` from candidate shape."""
    change_proximity = _compute_change_proximity(diff_anchors, scope_id, graph, run_context)
    seam_exposure = _seam_exposure_value(seam_edges)
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
    graph: nx.DiGraph | None = None,
    run_context: "RunContext | None" = None,
) -> Candidate:
    import hashlib

    da_list = list(diff_anchors or [])
    se_list = list(seam_edges or [])
    payload = f"{scope_id}|{seed_type.value}|{sorted(da_list)}|{sorted(se_list)}"
    cid = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]
    resolved_seams = _resolve_seam_edges(se_list, run_context, graph)
    change_proximity, seam_exposure = _derive_vector_dimensions(
        scope_id=scope_id,
        diff_anchors=da_list,
        seam_edges=resolved_seams,
        graph=graph,
        run_context=run_context,
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
        language_path=_language_path_from_seams(resolved_seams),
        language_pair=language_pair,
        seam_edges=resolved_seams,
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
    graph: nx.DiGraph | None = None,
    run_context: "RunContext | None" = None,
) -> Candidate:
    """Used by :mod:`candidate_identifier` for manifest-driven seeds (explicit id)."""
    da_list = list(diff_anchors or [])
    se_list = list(seam_edge_ids or [])
    resolved_seams = _resolve_seam_edges(se_list, run_context, graph)
    change_proximity, seam_exposure = _derive_vector_dimensions(
        scope_id=scope_id,
        diff_anchors=da_list,
        seam_edges=resolved_seams,
        graph=graph,
        run_context=run_context,
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
        language_path=_language_path_from_seams(resolved_seams),
        language_pair=language_pair,
        seam_edges=resolved_seams,
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
    "read_source_text_safely",
    "simple_spec",
]
