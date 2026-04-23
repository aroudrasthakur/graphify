"""Helpers to decide whether LLM text cites bundle graph ids (nodes, edges, seams)."""
from __future__ import annotations

from depos.analysis.schemas import ContextBundle


def bundle_citation_tokens(bundle: ContextBundle) -> set[str]:
    """Return candidate substrings that count as a structural citation."""
    out: set[str] = set()
    for val in (bundle.bundle_id, bundle.candidate_id, bundle.scope_id):
        if val:
            out.add(str(val))
    sid = bundle.scope_id
    if sid.startswith("node:") and len(sid) > 5:
        out.add(sid[5:])
    if bundle.scope_node_id:
        out.add(str(bundle.scope_node_id))
    for s in bundle.code_snippets:
        if s.node_id:
            out.add(str(s.node_id))
    for e in bundle.cross_language_seams:
        for part in (e.edge_id, e.source, e.target):
            if part:
                out.add(str(part))
    for te in bundle.taint_edges:
        for part in (te.source_node, te.sink_node, *te.intermediate_path):
            if part:
                out.add(str(part))
    return {t for t in out if len(t) >= 4}


def evidence_cites_bundle(evidence_text: str, bundle: ContextBundle) -> bool:
    if not (evidence_text and evidence_text.strip()):
        return False
    lowered = evidence_text.lower()
    for token in bundle_citation_tokens(bundle):
        if token.lower() in lowered:
            return True
    return False


__all__ = ["bundle_citation_tokens", "evidence_cites_bundle"]
