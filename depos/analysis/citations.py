"""Helpers to decide whether LLM text cites bundle graph ids (nodes, edges, seams)."""
from __future__ import annotations

import re

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


def _node_citation_tokens(bundle: ContextBundle) -> set[str]:
    tokens = set(bundle_citation_tokens(bundle))
    tokens.update(str(node_id) for node_id in bundle.callers if node_id)
    tokens.update(str(node_id) for node_id in bundle.callees if node_id)
    tokens.update(str(node_id) for node_id in bundle.seam_neighbor_texts if node_id)
    return {token for token in tokens if len(token) >= 1}


def _edge_citation_tokens(bundle: ContextBundle) -> set[str]:
    out: set[str] = set()
    for edge in bundle.cross_language_seams:
        if edge.edge_id:
            out.add(str(edge.edge_id))
    return out


def _taint_citation_tokens(bundle: ContextBundle) -> set[str]:
    out: set[str] = set()
    for edge in bundle.taint_edges:
        for step in edge.intermediate_path:
            if step:
                out.add(str(step))
    return out


_EXPLICIT_CITATION_RE = re.compile(r"\[(node|edge|taint):([^\]]+)\]", re.I)


def evidence_cites_bundle(evidence_text: str, bundle: ContextBundle) -> bool:
    if not (evidence_text and evidence_text.strip()):
        return False
    node_tokens = {token.lower() for token in _node_citation_tokens(bundle)}
    edge_tokens = {token.lower() for token in _edge_citation_tokens(bundle)}
    taint_tokens = {token.lower() for token in _taint_citation_tokens(bundle)}
    for kind, raw_token in _EXPLICIT_CITATION_RE.findall(evidence_text):
        token = raw_token.strip().lower()
        if kind.lower() == "node":
            if token in node_tokens or (token.startswith("node:") and token[5:] in node_tokens):
                return True
        elif kind.lower() == "edge":
            if token in edge_tokens:
                return True
        elif kind.lower() == "taint":
            if token in taint_tokens:
                return True
    lowered = evidence_text.lower()
    for token in _node_citation_tokens(bundle) | _edge_citation_tokens(bundle) | _taint_citation_tokens(bundle):
        if token.lower() in lowered:
            return True
    return False


__all__ = ["bundle_citation_tokens", "evidence_cites_bundle"]
