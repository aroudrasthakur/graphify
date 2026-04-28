"""Join IntentTraceHints (from intent-context build) to path candidates."""
from __future__ import annotations

from depos.intent_context.schemas import IntentTraceHints, IntentUnit
from depos.intent_graph.schemas import GicEvidenceRef


def normalize_oft_id(s: str | None) -> str:
    if not s:
        return ""
    return s.replace("`", "").strip()


def paths_and_refs_from_trace_hints(
    unit: IntentUnit,
    trace_hints: IntentTraceHints | None,
    chunks: dict[str, tuple[str, int, int]],
) -> tuple[list[str], list[GicEvidenceRef]]:
    """Map ``intent_trace_hints.json`` nodes and embedded tags to filesystem paths."""
    oid = normalize_oft_id(getattr(unit, "oft_spec_item_id", None))
    if not trace_hints or not oid:
        return [], []
    refs: list[GicEvidenceRef] = []
    paths: list[str] = []

    for node in trace_hints.nodes:
        nid = normalize_oft_id(getattr(node, "id", None))
        if nid != oid:
            continue
        cid = getattr(node, "source_chunk_id", None)
        if cid and cid in chunks:
            rel = chunks[cid][0].strip()
            if rel:
                paths.append(rel)
                refs.append(
                    GicEvidenceRef(
                        kind="trace_hint",
                        detail=f"intent_trace_hints node → chunk={cid}",
                        source_file=rel,
                    ),
                )

    seen_path = set(paths)
    for d in getattr(trace_hints, "coverage_tags", []) or []:
        if not isinstance(d, dict):
            continue
        cov_raw = str(d.get("covered_spec_id") or "").strip()
        cov = normalize_oft_id(cov_raw)
        if not oid or not cov:
            continue
        if cov not in oid and oid not in cov:
            continue
        fname = str(d.get("file") or "").strip()
        line = d.get("line")
        ln = int(line) if isinstance(line, int) else None
        if not fname:
            continue
        if fname not in seen_path:
            paths.append(fname)
            seen_path.add(fname)
        refs.append(
            GicEvidenceRef(
                kind="trace_hint",
                detail="intent_trace_hints.coverage_tags",
                source_file=fname,
                line=ln,
            ),
        )

    uniq: list[str] = []
    s2: set[str] = set()
    for p in paths:
        if p not in s2:
            s2.add(p)
            uniq.append(p)
    return uniq, refs
