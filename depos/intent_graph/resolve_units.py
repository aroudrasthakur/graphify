"""Resolve IntentUnit rows against a GraphPathIndex."""
from __future__ import annotations

from pathlib import Path

from depos.intent_graph.graph_index import GraphPathIndex, normalize_key_any
from depos.intent_graph.schemas import GicEvidenceRef, GicUnitResult
from depos.intent_context.schemas import CoverageTagRecord, IntentTraceHints, IntentUnit

from depos.intent_graph.trace_join import paths_and_refs_from_trace_hints


def _tier_str(u: IntentUnit) -> str:
    return getattr(u, "effective_tier", None) or "P2"


def _uniq_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        ps = p.strip()
        if ps and ps not in seen:
            seen.add(ps)
            out.append(ps)
    return out


def _suffix_match_path(rp: str, idx: GraphPathIndex) -> str | None:
    nk = normalize_key_any(rp, idx.repo_root)
    if idx.has_file(rp):
        return rp
    leaf = Path(rp).name
    best: str | None = None
    for fpath in idx.files_set():
        if Path(fpath).name == leaf:
            best = fpath
            break
    if best and idx.has_file(best):
        return best
    return None


def resolve_unit(
    unit: IntentUnit,
    *,
    chunks: dict[str, tuple[str, int, int]],
    coverage_tags: list[CoverageTagRecord],
    trace_hints: IntentTraceHints | None,
    idx: GraphPathIndex,
    repo_root: Path,
) -> GicUnitResult:
    ew = float(unit.effective_weight)
    tier = _tier_str(unit)
    refs: list[GicEvidenceRef] = []

    candidate_paths: list[str] = []
    for h in unit.scope_hints:
        candidate_paths.append(h)
    for ev in unit.evidence:
        tup = chunks.get(ev.chunk_id)
        if tup:
            candidate_paths.append(tup[0])
    for tg in coverage_tags:
        if unit.oft_spec_item_id:
            oid = unit.oft_spec_item_id.replace("`", "").strip()
            if oid and tg.covered_spec_id and tg.covered_spec_id in oid:
                candidate_paths.append(tg.source_relpath)

    hint_paths, hint_refs = paths_and_refs_from_trace_hints(unit, trace_hints, chunks)
    candidate_paths.extend(hint_paths)

    candidate_paths = _uniq_paths(candidate_paths)

    if unit.oft_covers or unit.oft_spec_item_id:
        refs.append(
            GicEvidenceRef(
                kind="oft_covers",
                detail=str(unit.oft_covers or unit.oft_spec_item_id or ""),
            )
        )

    refs.extend(hint_refs)

    if not candidate_paths:
        if unit.oft_covers or unit.oft_spec_item_id:
            return GicUnitResult(
                unit_id=unit.unit_id,
                natural_language=unit.natural_language,
                effective_tier=tier,
                effective_weight=ew,
                extractor=unit.extractor,
                status="partial",
                unresolved_reason="none",
                structural_confidence=0.45,
                evidence=refs,
            )
        return GicUnitResult(
            unit_id=unit.unit_id,
            natural_language=unit.natural_language,
            effective_tier=tier,
            effective_weight=ew,
            extractor=unit.extractor,
            status="unresolved",
            unresolved_reason="empty_scope_hints",
            structural_confidence=0.0,
            evidence=refs,
        )

    def _line_hint_for_path(rel: str) -> int | None:
        for ev in unit.evidence:
            tup = chunks.get(ev.chunk_id)
            if not tup or tup[0] != rel:
                continue
            if ev.start_line is not None:
                return ev.start_line
        for tg in coverage_tags:
            nk_t = normalize_key_any(tg.source_relpath, repo_root)
            nk_r = normalize_key_any(rel, repo_root)
            if nk_t == nk_r:
                return tg.line
        return None

    matched_any_file = False
    had_nodes = False
    best_supported = False

    for rp0 in candidate_paths:
        rp = _suffix_match_path(rp0, idx)
        if rp is None:
            continue
        matched_any_file = True
        nodes_here = idx.nodes_for_file(rp)
        if nodes_here:
            had_nodes = True

        line_hint = _line_hint_for_path(rp0) or _line_hint_for_path(rp)
        nid, res_ln = idx.best_node_for_line(rp, line_hint)

        refs.append(
            GicEvidenceRef(
                kind="scope_hint_path",
                detail=f"path={rp}",
                node_id=nid,
                source_file=rp,
                line=res_ln,
            )
        )

        if line_hint is not None and res_ln is not None and abs(res_ln - line_hint) <= 5:
            best_supported = True

    if not matched_any_file:
        return GicUnitResult(
            unit_id=unit.unit_id,
            natural_language=unit.natural_language,
            effective_tier=tier,
            effective_weight=ew,
            extractor=unit.extractor,
            status="unresolved",
            unresolved_reason="no_matching_file",
            structural_confidence=0.0,
            evidence=refs,
        )

    if matched_any_file and not had_nodes:
        return GicUnitResult(
            unit_id=unit.unit_id,
            natural_language=unit.natural_language,
            effective_tier=tier,
            effective_weight=ew,
            extractor=unit.extractor,
            status="unresolved",
            unresolved_reason="no_graph_nodes_for_file",
            structural_confidence=0.2,
            evidence=refs,
        )

    if best_supported:
        status = "supported"
        sc = 1.0
    else:
        status = "partial"
        sc = 0.75

    return GicUnitResult(
        unit_id=unit.unit_id,
        natural_language=unit.natural_language,
        effective_tier=tier,
        effective_weight=ew,
        extractor=unit.extractor,
        status=status,  # type: ignore[arg-type]
        unresolved_reason="none",
        structural_confidence=sc,
        evidence=refs,
    )
